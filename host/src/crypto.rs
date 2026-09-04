//! Safe wrappers over crypto/include/riscv_qubic_crypto.h + stock_host.h (linked by build.rs).

extern "C" {
    fn qubic_k12(input: *const u8, input_len: usize, out32: *mut u8);
    fn fourq_verify(pk: *const u8, sig: *const u8, digest: *const u8) -> i32;
    fn qubic_seed_to_subseed(seed: *const u8, subseed: *mut u8) -> i32;
    fn qubic_subseed_to_keys(subseed: *const u8, priv_: *mut u8, pub_: *mut u8);
    fn qubic_sign(subseed: *const u8, pub_: *const u8, digest: *const u8, sig: *mut u8);
    fn qubic_identity(pub_: *const u8, out61: *mut u8, lower_case: i32);
}

pub fn k12(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { qubic_k12(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    out
}

pub fn verify(pk: &[u8; 32], sig: &[u8; 64], digest: &[u8; 32]) -> bool {
    unsafe { fourq_verify(pk.as_ptr(), sig.as_ptr(), digest.as_ptr()) == 1 }
}

/// seed = 55 lowercase a-z chars; None on a bad seed.
pub fn seed_to_subseed(seed: &str) -> Option<[u8; 32]> {
    if seed.len() != 55 {
        return None;
    }
    let mut subseed = [0u8; 32];
    let ok = unsafe { qubic_seed_to_subseed(seed.as_ptr(), subseed.as_mut_ptr()) };
    (ok != 0).then_some(subseed)
}

/// Returns (private key, public key).
pub fn subseed_to_keys(subseed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (mut priv_, mut pub_) = ([0u8; 32], [0u8; 32]);
    unsafe { qubic_subseed_to_keys(subseed.as_ptr(), priv_.as_mut_ptr(), pub_.as_mut_ptr()) };
    (priv_, pub_)
}

pub fn sign(subseed: &[u8; 32], pub_: &[u8; 32], digest: &[u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    unsafe { qubic_sign(subseed.as_ptr(), pub_.as_ptr(), digest.as_ptr(), sig.as_mut_ptr()) };
    sig
}

/// 60-char Qubic identity (upper case).
pub fn identity(pub_: &[u8; 32]) -> String {
    let mut out = [0u8; 61];
    unsafe { qubic_identity(pub_.as_ptr(), out.as_mut_ptr(), 0) };
    String::from_utf8_lossy(&out[..60]).into_owned()
}

/// Seed -> (subseed, pubkey). Panics on a malformed seed.
pub fn keypair(seed: &str) -> ([u8; 32], [u8; 32]) {
    let subseed = seed_to_subseed(seed).unwrap_or_else(|| panic!("bad seed: {seed:?}"));
    (subseed, subseed_to_keys(&subseed).1)
}
