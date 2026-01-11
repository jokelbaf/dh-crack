use num::bigint::BigUint;
use std::collections::HashMap;
use thiserror::Error;

pub const MODULUS: u128 = (1u128 << 64) - 59;
pub const GENERATOR: u128 = 5;

#[derive(Debug, Error)]
pub enum DhCrackError {
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid key length: expected 8 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("invalid public key: value cannot be zero")]
    ZeroPublicKey,
    #[error("failed to compute discrete logarithm")]
    DiscreteLogFailed,
}

pub type Result<T> = std::result::Result<T, DhCrackError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhKey {
    value: u128,
}

impl DhKey {
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(DhCrackError::InvalidKeyLength(bytes.len()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        let value = u64::from_le_bytes(arr) as u128;
        if value == 0 {
            return Err(DhCrackError::ZeroPublicKey);
        }
        Ok(Self { value })
    }

    pub fn from_hex_le(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes_le(&bytes)
    }

    pub fn from_u64(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(DhCrackError::ZeroPublicKey);
        }
        Ok(Self {
            value: value as u128,
        })
    }

    pub fn to_bytes_le(&self) -> [u8; 8] {
        (self.value as u64).to_le_bytes()
    }

    pub fn to_hex_le(&self) -> String {
        hex::encode(self.to_bytes_le())
    }

    pub fn as_u64(&self) -> u64 {
        self.value as u64
    }

    pub fn as_u128(&self) -> u128 {
        self.value
    }
}

pub fn crack_dh(public_key: &DhKey) -> Result<DhKey> {
    let private = pohlig_hellman(GENERATOR, public_key.value, MODULUS)
        .ok_or(DhCrackError::DiscreteLogFailed)?;
    Ok(DhKey { value: private })
}

pub fn dh_exchange(private_key: &DhKey) -> DhKey {
    let public = mod_pow(GENERATOR, private_key.value, MODULUS);
    DhKey { value: public }
}

pub fn dh_secret(peer_public: &DhKey, private_key: &DhKey) -> DhKey {
    let secret = mod_pow(peer_public.value, private_key.value, MODULUS);
    DhKey { value: secret }
}

#[inline]
fn mod_mul(a: u128, b: u128, m: u128) -> u128 {
    (a * b) % m
}

fn mod_pow(mut base: u128, mut exp: u128, m: u128) -> u128 {
    if m == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, m);
        }
        exp >>= 1;
        base = mod_mul(base, base, m);
    }
    result
}

fn mod_inverse(a: u128, m: u128) -> Option<u128> {
    let a = a as i128;
    let m = m as i128;
    let (mut old_r, mut r) = (a, m);
    let (mut old_s, mut s) = (1i128, 0i128);

    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (s, old_s - q * s);
    }

    if old_r != 1 {
        return None;
    }

    Some(((old_s % m + m) % m) as u128)
}

fn baby_step_giant_step(g: u128, h: u128, p: u128, order: u128) -> Option<u128> {
    let m = (order as f64).sqrt().ceil() as u128 + 1;

    let mut table: HashMap<u128, u128> = HashMap::with_capacity(m as usize);
    let mut g_j: u128 = 1;
    for j in 0..m {
        table.insert(g_j, j);
        g_j = mod_mul(g_j, g, p);
    }

    let g_m = mod_pow(g, m, p);
    let g_m_inv = mod_inverse(g_m, p)?;

    let mut gamma = h;
    for i in 0..m {
        if let Some(&j) = table.get(&gamma) {
            let x = i * m + j;
            if mod_pow(g, x, p) == h {
                return Some(x);
            }
        }
        gamma = mod_mul(gamma, g_m_inv, p);
    }

    None
}

fn factor_order(mut n: u128) -> Vec<(u128, u32)> {
    let mut factors = Vec::new();
    let mut d = 2u128;

    while d * d <= n {
        if n.is_multiple_of(d){
            let mut exp = 0u32;
            while n.is_multiple_of(d) {
                n /= d;
                exp += 1;
            }
            factors.push((d, exp));
        }
        d += 1;
    }
    if n > 1 {
        factors.push((n, 1));
    }
    factors
}

fn pohlig_hellman(g: u128, h: u128, p: u128) -> Option<u128> {
    let order = p - 1;
    let factors = factor_order(order);

    let mut residues: Vec<BigUint> = Vec::new();
    let mut moduli: Vec<BigUint> = Vec::new();

    for (prime, exp) in &factors {
        let prime_power = prime.pow(*exp);
        let exp_factor = order / prime_power;
        let g_i = mod_pow(g, exp_factor, p);
        let h_i = mod_pow(h, exp_factor, p);

        let x_i = baby_step_giant_step(g_i, h_i, p, prime_power)?;

        residues.push(BigUint::from(x_i));
        moduli.push(BigUint::from(prime_power));
    }

    let result = chinese_remainder_theorem(&residues, &moduli)?;
    let result_u128: u128 = result.to_string().parse().ok()?;

    if mod_pow(g, result_u128, p) == h {
        Some(result_u128)
    } else {
        None
    }
}

fn chinese_remainder_theorem(residues: &[BigUint], moduli: &[BigUint]) -> Option<BigUint> {
    use num::Zero;

    let prod: BigUint = moduli.iter().product();
    let mut sum = BigUint::zero();

    for (r_i, m_i) in residues.iter().zip(moduli.iter()) {
        let p_i = &prod / m_i;
        let inv = mod_inverse_big(&p_i, m_i)?;
        sum += r_i * &p_i * inv;
    }

    Some(sum % prod)
}

fn mod_inverse_big(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num::{One, Zero};

    let mut old_r = a.clone();
    let mut r = m.clone();
    let mut old_s: num::BigInt = One::one();
    let mut s: num::BigInt = Zero::zero();

    while !r.is_zero() {
        let q = &old_r / &r;
        let q_int: num::BigInt = q.clone().into();

        let new_r = &old_r % &r;
        old_r = r;
        r = new_r;

        let new_s = &old_s - &q_int * &s;
        old_s = s;
        s = new_s;
    }

    if old_r != One::one() {
        return None;
    }

    let m_int: num::BigInt = m.clone().into();
    let result = ((old_s % &m_int) + &m_int) % &m_int;
    Some(result.to_biguint().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack_known_key() {
        let public = DhKey::from_hex_le("2fcdd27bf0dfe780").unwrap();
        let private = crack_dh(&public).unwrap();
        assert_eq!(private.to_hex_le(), "cbed2a7d9585b611");
    }

    #[test]
    fn test_dh_exchange() {
        let private = DhKey::from_hex_le("cbed2a7d9585b611").unwrap();
        let public = dh_exchange(&private);
        assert_eq!(public.to_hex_le(), "2fcdd27bf0dfe780");
    }

    #[test]
    fn test_roundtrip() {
        let public = DhKey::from_hex_le("7b074553b055f69d").unwrap();
        let private = crack_dh(&public).unwrap();
        let recomputed = dh_exchange(&private);
        assert_eq!(public, recomputed);
    }
}
