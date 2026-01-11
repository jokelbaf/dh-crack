# dh-crack

A Rust implementation of the Pohlig-Hellman algorithm for solving discrete logarithm problems in weak Diffie-Hellman key exchanges. Cracks DH private keys when using small modulus (2^64 - 59) and generator 5.

## CLI

### Installation

```bash
cargo install --git https://github.com/jokelbaf/dh-crack.git
```

### Usage

```bash
# Crack a DH private key from a public key (hex, little-endian)
dh-crack 7b074553b055f69d
```

Example output:
```
Private key: 36e6e76ef56b3f76
```

## Library

### Installation

Add to your `Cargo.toml`:

```bash
cargo add --git https://github.com/jokelbaf/dh-crack.git
```

### Usage

```rust
use dh_crack::{DhKey, crack_dh, dh_exchange, dh_secret};

// Crack a private key from a public key
let public_key = DhKey::from_hex_le("7b074553b055f69d").unwrap();
let private_key = crack_dh(&public_key).unwrap();
println!("Private key: {}", private_key.to_hex_le());

// Generate public key from private key
let private = DhKey::from_hex_le("cbed2a7d9585b611").unwrap();
let public = dh_exchange(&private);

// Compute shared secret
let peer_public = DhKey::from_hex_le("2fcdd27bf0dfe780").unwrap();
let shared_secret = dh_secret(&peer_public, &private);
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
