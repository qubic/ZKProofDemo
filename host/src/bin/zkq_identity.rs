//! zkq-identity <60-char identity | 64-hex pubkey>: prints both forms, verifies the checksum.
use host::identity::{hex32, identity_to_pubkey, pubkey_to_identity};

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| { eprintln!("usage: zkq-identity <identity|pubkey-hex>"); std::process::exit(2) });
    let pk: [u8; 32] = if arg.len() == 64 {
        (0..32).map(|i| u8::from_str_radix(&arg[2 * i..2 * i + 2], 16).expect("bad hex"))
            .collect::<Vec<_>>().try_into().unwrap()
    } else {
        identity_to_pubkey(&arg).unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(1) })
    };
    println!("identity: {}", pubkey_to_identity(&pk));
    println!("pubkey:   {}", hex32(&pk));
}
