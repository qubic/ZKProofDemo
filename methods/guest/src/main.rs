//! zkq-quorum guest: proves the SPEC.md "Wire formats v2" statement; violations panic (no proof).

//! Frame order must match host/src/fixture.rs `to_env` (positional `len u32 LE | bytes` frames).

//! Journal (44 bytes): epoch u32 LE | queryId u64 LE | K12(reply).
#![no_main]
risc0_zkvm::guest::entry!(main);
use risc0_zkvm::guest::env;

mod bigint2; // zkq_* shims referenced by the C core

extern "C" {
    // int fourq_verify(const uint8_t pk[32], const uint8_t sig[64], const uint8_t digest[32]); 1 = valid
    fn fourq_verify(pubkey: *const u8, sig: *const u8, digest: *const u8) -> i32;
    // void qubic_k12(const uint8_t* in, size_t inLen, uint8_t out32[32]);
    fn qubic_k12(input: *const u8, input_len: usize, out32: *mut u8);
}

const NUMBER_OF_COMPUTORS: usize = 676;
const QUORUM: usize = 451;
const SIGNATURE_SIZE: usize = 64;
const PACKET_SIZE: usize = 2 + NUMBER_OF_COMPUTORS * 32 + SIGNATURE_SIZE;
/// Bytes covered by the arbitrator signature (everything but the signature).
const PACKET_SIGNED_SIZE: usize = PACKET_SIZE - SIGNATURE_SIZE;
const TX_HEADER_SIZE: usize = 80;
const COMMIT_ITEM_SIZE: usize = 8 + 32 + 32;
const QUERY_INPUT_TYPE: u16 = 10;
const COMMIT_INPUT_TYPE: u16 = 6;
const REVEAL_INPUT_TYPE: u16 = 7;
const JOURNAL_SIZE: usize = 4 + 8 + 32;

/// Arbitrator pubkey from config/deploy.env via build.rs; baked into the image ID.
const ARBITRATOR_PUBKEY: [u8; 32] = hex32(env!("ZKQ_ARBITRATOR_PUBKEY_HEX"));

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "ZKQ_ARBITRATOR_PUBKEY_HEX must be 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, b'A'..=b'F' => c - b'A' + 10, _ => panic!("bad hex") }
}

/// 8-byte aligned buffers: the C core reads inputs as uint64_t words.
#[repr(align(8))]
struct Aligned32([u8; 32]);
#[repr(align(8))]
struct Aligned64([u8; 64]);

/// Reads a host `write_frame` (len u32 LE | bytes) with the stable API: 2 syscalls, no serde.
fn read_frame() -> Vec<u8> {
    let mut len = [0u32; 1];
    env::read_slice(&mut len);
    let mut bytes = vec![0u8; len[0] as usize];
    env::read_slice(&mut bytes);
    bytes
}

fn k12(data: &[u8]) -> Aligned32 {
    let mut out = Aligned32([0u8; 32]);
    unsafe { qubic_k12(data.as_ptr(), data.len(), out.0.as_mut_ptr()) };
    out
}

fn schnorrq_verify(pubkey: &[u8], sig: &[u8], digest: &Aligned32) -> bool {
    let mut pk = Aligned32([0u8; 32]);
    pk.0.copy_from_slice(pubkey);
    let mut s = Aligned64([0u8; 64]);
    s.0.copy_from_slice(sig);
    unsafe { fourq_verify(pk.0.as_ptr(), s.0.as_ptr(), digest.0.as_ptr()) == 1 }
}

/// Parsed Qubic transaction (borrowed from the raw bytes).
struct Tx<'a> {
    source: &'a [u8],
    dest_is_zero: bool,
    amount: i64,
    tick: u32,
    input_type: u16,
    input: &'a [u8],
    sig: &'a [u8],
}

/// None unless `len == 80 + inputSize + 64`.
fn parse_tx(tx: &[u8]) -> Option<Tx<'_>> {
    if tx.len() < TX_HEADER_SIZE + SIGNATURE_SIZE {
        return None;
    }
    let input_size = u16::from_le_bytes([tx[78], tx[79]]) as usize;
    if tx.len() != TX_HEADER_SIZE + input_size + SIGNATURE_SIZE {
        return None;
    }
    Some(Tx {
        source: &tx[..32],
        dest_is_zero: tx[32..64].iter().all(|&b| b == 0),
        amount: i64::from_le_bytes(tx[64..72].try_into().unwrap()),
        tick: u32::from_le_bytes(tx[72..76].try_into().unwrap()),
        input_type: u16::from_le_bytes([tx[76], tx[77]]),
        input: &tx[TX_HEADER_SIZE..TX_HEADER_SIZE + input_size],
        sig: &tx[TX_HEADER_SIZE + input_size..],
    })
}

/// SchnorrQ(source) over K12(tx bytes minus signature).
fn tx_signature_valid(raw: &[u8], tx: &Tx) -> bool {
    schnorrq_verify(tx.source, tx.sig, &k12(&raw[..raw.len() - SIGNATURE_SIZE]))
}

fn pubkey_at(pubkeys: &[u8], i: usize) -> &[u8] {
    &pubkeys[i * 32..i * 32 + 32]
}

/// Index of `key` in the list via the sorted index, or None.
fn find_computor(pubkeys: &[u8], sorted: &[u16], key: &[u8]) -> Option<usize> {
    sorted
        .binary_search_by(|&i| pubkey_at(pubkeys, i as usize).cmp(key))
        .ok()
        .map(|pos| sorted[pos] as usize)
}

/// Computor index this commit counts for (SPEC step 4), or None. Cheap checks first, signature last.
fn check_commit(
    raw: &[u8],
    pubkeys: &[u8],
    sorted: &[u16],
    seen: &[bool; NUMBER_OF_COMPUTORS],
    query_id: &[u8; 8],
    query_tick: u32,
    reply_digest: &[u8; 32],
    reply: &[u8],
) -> Option<usize> {
    let tx = parse_tx(raw)?;
    if tx.input_type != COMMIT_INPUT_TYPE || !tx.dest_is_zero || tx.amount != 0 || tx.tick <= query_tick {
        return None;
    }
    let idx = find_computor(pubkeys, sorted, tx.source)?;
    if seen[idx] {
        return None;
    }
    let mut proof_msg = Vec::with_capacity(reply.len() + 2);
    proof_msg.extend_from_slice(reply);
    proof_msg.extend_from_slice(&(idx as u16).to_le_bytes());
    let knowledge_proof = k12(&proof_msg);
    let matched = tx.input.chunks_exact(COMMIT_ITEM_SIZE).any(|item| {
        item[..8] == query_id[..] && item[8..40] == reply_digest[..] && item[40..72] == knowledge_proof.0[..]
    });
    if !matched || !tx_signature_valid(raw, &tx) {
        return None;
    }
    Some(idx)
}

fn main() {
    let packet = read_frame();
    let query_id_bytes = read_frame();
    let query_tx = read_frame();
    let reply = read_frame();
    let commits = read_frame();
    let reveal_tx = read_frame();

    assert_eq!(packet.len(), PACKET_SIZE, "computors packet must be {} bytes", PACKET_SIZE);
    let query_id: [u8; 8] = query_id_bytes.as_slice().try_into().expect("queryId frame must be 8 bytes");
    let query_id_u64 = u64::from_le_bytes(query_id);

    // 1. Arbitrator-signed list, epoch != 0, distinct pubkeys.
    let packet_digest = k12(&packet[..PACKET_SIGNED_SIZE]);
    if !schnorrq_verify(&ARBITRATOR_PUBKEY, &packet[PACKET_SIGNED_SIZE..], &packet_digest) {
        panic!("computor list is not signed by the arbitrator");
    }
    let epoch = u16::from_le_bytes([packet[0], packet[1]]);
    assert!(epoch != 0, "epoch 0 is not attestable");
    let pubkeys = &packet[2..PACKET_SIGNED_SIZE];
    let sorted = reject_duplicate_pubkeys(pubkeys);

    // 2. Query transaction.
    let q = parse_tx(&query_tx).expect("query tx: length != 80 + inputSize + 64");
    assert_eq!(q.input_type, QUERY_INPUT_TYPE, "query tx: inputType must be 10");
    assert!(q.dest_is_zero, "query tx: destination must be zero");
    assert!(tx_signature_valid(&query_tx, &q), "query tx: invalid signature");
    assert_eq!(q.tick as u64, query_id_u64 >> 31, "query tx: tick != queryId >> 31");
    let query_tick = q.tick;

    let reply_digest = k12(&reply);

    // 3. Reveal transaction.
    let r = parse_tx(&reveal_tx).expect("reveal tx: length != 80 + inputSize + 64");
    assert_eq!(r.input_type, REVEAL_INPUT_TYPE, "reveal tx: inputType must be 7");
    assert!(r.dest_is_zero, "reveal tx: destination must be zero");
    assert_eq!(r.amount, 0, "reveal tx: amount must be 0");
    assert!(find_computor(pubkeys, &sorted, r.source).is_some(), "reveal tx: source not in computor list");
    assert!(tx_signature_valid(&reveal_tx, &r), "reveal tx: invalid signature");
    assert!(
        r.input.len() == 8 + reply.len() && r.input[..8] == query_id[..] && r.input[8..] == reply[..],
        "reveal tx: input != queryId | reply"
    );

    // 4. Commit transactions: n u32 | n x (len u32 | bytes).
    let mut seen = [false; NUMBER_OF_COMPUTORS];
    let mut count = 0usize;
    assert!(commits.len() >= 4, "commits frame: missing count");
    let n = u32::from_le_bytes(commits[..4].try_into().unwrap()) as usize;
    let mut off = 4usize;
    for _ in 0..n {
        let len = u32::from_le_bytes(commits.get(off..off + 4).expect("commits frame: truncated length").try_into().unwrap()) as usize;
        off += 4;
        let raw = commits.get(off..off + len).expect("commits frame: truncated transaction");
        off += len;
        if let Some(idx) = check_commit(raw, pubkeys, &sorted, &seen, &query_id, query_tick, &reply_digest.0, &reply) {
            seen[idx] = true;
            count += 1;
            if count >= QUORUM {
                break; // quorum reached; skip remaining signature checks
            }
        }
    }
    if count < QUORUM {
        panic!("quorum not reached: {} valid distinct commits, need {}", count, QUORUM);
    }

    let mut journal = [0u8; JOURNAL_SIZE];
    journal[..4].copy_from_slice(&(epoch as u32).to_le_bytes());
    journal[4..12].copy_from_slice(&query_id);
    journal[12..].copy_from_slice(&reply_digest.0);
    env::commit_slice(&journal);
}

/// Rejects repeated pubkeys (would double-count a signer); returns indices sorted by pubkey for binary search.
fn reject_duplicate_pubkeys(pubkeys: &[u8]) -> Vec<u16> {
    let mut order: Vec<u16> = (0..NUMBER_OF_COMPUTORS as u16).collect();
    order.sort_unstable_by_key(|&i| pubkey_at(pubkeys, i as usize));
    for w in order.windows(2) {
        assert!(
            pubkey_at(pubkeys, w[0] as usize) != pubkey_at(pubkeys, w[1] as usize),
            "duplicate pubkey in computor list"
        );
    }
    order
}
