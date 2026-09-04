//! Runs schnorrq_vectors.txt on-target: 129-byte records pk|sig|digest|expected; panics on mismatch; journal = count.
#![no_main]
risc0_zkvm::guest::entry!(main);
use risc0_zkvm::guest::env;

#[path = "../bigint2.rs"]
mod bigint2; // zkq_* shims referenced by the C core

extern "C" {
    fn fourq_verify(pubkey: *const u8, sig: *const u8, digest: *const u8) -> i32;
}

const RECORD: usize = 32 + 64 + 32 + 1;

/// Reads a host `write_frame` (len u32 LE | bytes) with the stable API: 2 syscalls, no serde.
fn read_frame() -> Vec<u8> {
    let mut len = [0u32; 1];
    env::read_slice(&mut len);
    let mut bytes = vec![0u8; len[0] as usize];
    env::read_slice(&mut bytes);
    bytes
}

#[repr(align(8))]
struct Rec([u8; RECORD - 1]);

fn main() {
    let records = read_frame();
    assert_eq!(records.len() % RECORD, 0);
    let mut n = 0u32;
    for r in records.chunks_exact(RECORD) {
        let mut buf = Rec([0u8; RECORD - 1]);
        buf.0.copy_from_slice(&r[..RECORD - 1]);
        let (pk, sig, digest) = (buf.0.as_ptr(), buf.0[32..].as_ptr(), buf.0[96..].as_ptr());
        let got = unsafe { fourq_verify(pk, sig, digest) } == 1;
        assert_eq!(got, r[RECORD - 1] == 1, "vector {n} mismatch");
        n += 1;
    }
    env::commit_slice(&n.to_le_bytes());
}
