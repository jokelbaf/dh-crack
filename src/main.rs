use dh_crack::{DhKey, crack_dh};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <public_key_hex_le>", args[0]);
        eprintln!("Example: {} 7b074553b055f69d", args[0]);
        return ExitCode::from(1);
    }

    let hex = &args[1];

    if hex.len() != 16 {
        eprintln!("Error: public key must be exactly 16 hex characters (8 bytes)");
        return ExitCode::from(1);
    }

    let public_key = match DhKey::from_hex_le(hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };

    match crack_dh(&public_key) {
        Ok(private_key) => {
            println!("Private key: {}", private_key.to_hex_le());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
    }
}
