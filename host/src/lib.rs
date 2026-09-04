pub mod crypto;
pub mod fixture;

pub use hex::encode as hex;

#[path = "../../methods/guest/identity.rs"]
pub mod identity;

#[cfg(test)]
mod identity_tests {
    use super::identity::*;
    /// crypto/seeds/*_pubkey*.txt lines: `seed pubkey_hex identity` (or just hex); returns the hex fields.
    fn lines(p: &str) -> Vec<String> {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../").to_string() + p)
            .unwrap().lines()
            .filter_map(|l| l.split_whitespace().find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit())).map(String::from))
            .collect()
    }
    #[test]
    fn arbitrator_identity_roundtrip() {
        let hex = lines("crypto/seeds/arbitrator_pubkey.txt")[0].clone();
        let pk: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>().try_into().unwrap();
        let id = pubkey_to_identity(&pk);
        assert_eq!(id, "ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG");
        assert_eq!(identity_to_pubkey(&id).unwrap(), pk);
        assert!(identity_to_pubkey(&(id[..59].to_string() + "A")).is_err()); // checksum
    }
    #[test]
    fn all_computor_pubkeys_match_seed_file_identities() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../crypto/seeds/computor_pubkeys.txt")).unwrap();
        let mut n = 0;
        for l in text.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 { continue; }
            let pk: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&f[1][2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<_>>().try_into().unwrap();
            assert_eq!(pubkey_to_identity(&pk), f[2]);
            assert_eq!(identity_to_pubkey(f[2]).unwrap(), pk);
            n += 1;
        }
        assert_eq!(n, 676);
    }
    #[test]
    fn mainnet_arbitrator_decodes() {
        assert!(identity_to_pubkey("AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ").is_ok());
    }
}
