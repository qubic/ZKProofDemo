//! crypto/tests/vectors/*.txt through the native FFI (libs = riscv port + stock_qubic signing).
use host::crypto::{identity, k12, keypair, sign, verify};

fn vectors(name: &str) -> Vec<Vec<String>> {
    let path = format!("{}/../crypto/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e} (run crypto/tests/run_tests.sh)"))
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(String::from).collect())
        .collect()
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[test]
fn k12_vectors() {
    let v = vectors("k12_vectors.txt");
    for f in &v {
        let len: usize = f[0].parse().unwrap();
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        assert_eq!(hex::encode(k12(&input)), f[1], "K12 len {len}");
    }
    assert_eq!(v.len(), 701);
}

#[test]
fn schnorrq_vectors() {
    let v = vectors("schnorrq_vectors.txt");
    for f in &v {
        let expected = f[0] == "1";
        assert_eq!(verify(&arr(&f[1]), &arr(&f[2]), &arr(&f[3])), expected, "{}", f[4]);
    }
    assert_eq!(v.len(), 16);
}

#[test]
fn keygen_vectors() {
    let v = vectors("keygen_vectors.txt");
    for f in &v {
        let (subseed, pk) = keypair(&f[0]);
        assert_eq!(hex::encode(subseed), f[1]);
        assert_eq!(hex::encode(pk), f[3]);
        assert_eq!(identity(&pk), f[4]);
    }
    assert_eq!(v.len(), 677);
}

#[test]
fn sign_vectors() {
    let v = vectors("sign_vectors.txt");
    for f in &v {
        let (subseed, pk) = keypair(&f[0]);
        let digest: [u8; 32] = arr(&f[1]);
        let sig = sign(&subseed, &pk, &digest);
        assert_eq!(hex::encode(sig), f[2]);
        assert!(verify(&pk, &sig, &digest));
    }
    assert_eq!(v.len(), 34);
}

#[test]
fn spec_constants() {
    let (_, arb) = keypair("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
    assert_eq!(hex::encode(arb), "69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5");
    assert_eq!(identity(&arb), "ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG");
}
