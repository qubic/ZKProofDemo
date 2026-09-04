//! Builds ZKQFIX02 fixtures from crypto/seeds/ and executes the guest; mirrors crypto/tools/gen_fixture.c.
use host::crypto::{k12, keypair, sign};
use host::fixture::{decode_journal, Fixture, JOURNAL_SIZE, NUMBER_OF_COMPUTORS, QUORUM};
use methods::ZKQ_QUORUM_ELF;
use risc0_zkvm::default_executor;
use std::sync::OnceLock;

const MESSAGE: &[u8] = b"Hello ZK, this is Qubic!";
const EPOCH: u16 = 999;
const QUERY_TICK: u32 = 1_000_000;
const COMMIT_TICK: u32 = 1_000_004;
const REVEAL_TICK: u32 = 1_000_007;
const QUERY_FEE: i64 = 1000;

type Keypair = ([u8; 32], [u8; 32]); // (subseed, pubkey)

struct Keys {
    computors: Vec<Keypair>,
    arbitrator: Keypair,
    user: Keypair,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../crypto/seeds/");
        let read = |f: &str| -> Vec<String> {
            std::fs::read_to_string(format!("{root}{f}")).unwrap()
                .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
        };
        let computors: Vec<Keypair> = read("computor_seeds.txt").iter().map(|s| keypair(s)).collect();
        assert_eq!(computors.len(), NUMBER_OF_COMPUTORS);
        Keys {
            computors,
            arbitrator: keypair(&read("arbitrator_seed.txt")[0]),
            user: keypair(&"a".repeat(55)),
        }
    })
}

/// Raw signed Qubic transaction: header 80 | input | SchnorrQ(source, K12(header|input)).
fn tx(signer: &Keypair, amount: i64, tick: u32, input_type: u16, input: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(80 + input.len() + 64);
    t.extend_from_slice(&signer.1);
    t.extend_from_slice(&[0u8; 32]); // destination zero
    t.extend_from_slice(&amount.to_le_bytes());
    t.extend_from_slice(&tick.to_le_bytes());
    t.extend_from_slice(&input_type.to_le_bytes());
    t.extend_from_slice(&(input.len() as u16).to_le_bytes());
    t.extend_from_slice(input);
    let sig = sign(&signer.0, &signer.1, &k12(&t));
    t.extend_from_slice(&sig);
    t
}

fn packet() -> Vec<u8> {
    let k = keys();
    let mut p = EPOCH.to_le_bytes().to_vec();
    for (_, pk) in &k.computors {
        p.extend_from_slice(pk);
    }
    let sig = sign(&k.arbitrator.0, &k.arbitrator.1, &k12(&p));
    p.extend_from_slice(&sig);
    p
}

fn query_id() -> u64 {
    (QUERY_TICK as u64) << 31
}

fn query_tx() -> Vec<u8> {
    let mut input = 0u32.to_le_bytes().to_vec(); // oracleInterfaceIndex
    input.extend_from_slice(&60000u32.to_le_bytes()); // timeoutMilliseconds
    input.extend_from_slice(MESSAGE);
    tx(&keys().user, QUERY_FEE, QUERY_TICK, 10, &input)
}

fn commit_item(qid: u64, reply: &[u8], idx: u16) -> Vec<u8> {
    let mut item = qid.to_le_bytes().to_vec();
    item.extend_from_slice(&k12(reply));
    let mut proof_msg = reply.to_vec();
    proof_msg.extend_from_slice(&idx.to_le_bytes());
    item.extend_from_slice(&k12(&proof_msg));
    item
}

fn commit_tx(idx: usize, tick: u32, item: &[u8]) -> Vec<u8> {
    tx(&keys().computors[idx], 0, tick, 6, item)
}

fn good_commit(idx: usize) -> Vec<u8> {
    commit_tx(idx, COMMIT_TICK, &commit_item(query_id(), MESSAGE, idx as u16))
}

fn good_commits(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(good_commit).collect()
}

fn reveal_tx(input: &[u8]) -> Vec<u8> {
    tx(&keys().computors[0], 0, REVEAL_TICK, 7, input)
}

fn fixture(commit_txs: Vec<Vec<u8>>) -> Fixture {
    let mut reveal_input = query_id().to_le_bytes().to_vec();
    reveal_input.extend_from_slice(MESSAGE);
    Fixture {
        computors_packet: packet(),
        query_id: query_id(),
        query_tx: query_tx(),
        reply: MESSAGE.to_vec(),
        commit_txs,
        reveal_tx: reveal_tx(&reveal_input),
    }
}

/// Executes the guest; Ok((journal, cycles)) or Err(first line of the guest error).
fn execute(fx: &Fixture) -> Result<(Vec<u8>, u64), String> {
    // Every fixture also survives the file format.
    assert_eq!(&Fixture::parse(&fx.serialize()).unwrap(), fx);
    default_executor()
        .execute(fx.to_env(), ZKQ_QUORUM_ELF)
        .map(|info| (info.journal.bytes.clone(), info.cycles()))
        .map_err(|e| e.to_string())
}

fn expect_quorum_fail(fx: &Fixture, counted: usize) {
    let err = execute(fx).expect_err("guest must reject");
    let want = format!("quorum not reached: {counted} valid distinct commits, need {QUORUM}");
    assert!(err.contains(&want), "wrong rejection: {err}\nwant: {want}");
}

#[test]
fn quorum_ok_500_commits() {
    let fx = fixture(good_commits(500));
    let (journal, cycles) = execute(&fx).expect("guest must accept");
    assert_eq!(journal.len(), JOURNAL_SIZE);
    assert_eq!(journal, fx.expected_journal());
    let (epoch, qid, digest) = decode_journal(&journal);
    assert_eq!(epoch, EPOCH as u32);
    assert_eq!(qid, query_id());
    assert_eq!(digest, k12(MESSAGE));
    println!("quorum_ok (500 commits): {cycles} cycles");
}

#[test]
fn quorum_fail_300_good_200_corrupted() {
    let mut commits = good_commits(500);
    for c in &mut commits[300..] {
        let n = c.len();
        c[n - 64 + 7] ^= 0xff; // corrupt the signature
    }
    expect_quorum_fail(&fixture(commits), 300);
}

#[test]
fn wrong_reply_digest_not_counted() {
    let mut commits = good_commits(10);
    for i in 10..15 {
        commits.push(commit_tx(i, COMMIT_TICK, &commit_item(query_id(), b"another reply", i as u16)));
    }
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn wrong_knowledge_proof_not_counted() {
    let mut commits = good_commits(10);
    for i in 10..15 {
        commits.push(commit_tx(i, COMMIT_TICK, &commit_item(query_id(), MESSAGE, i as u16 + 1)));
    }
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn replayed_query_id_not_counted() {
    let mut commits = good_commits(10);
    for i in 10..15 {
        commits.push(commit_tx(i, COMMIT_TICK, &commit_item(query_id() + 1, MESSAGE, i as u16)));
    }
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn duplicate_computor_commits_counted_once() {
    let mut commits = good_commits(10);
    for i in 0..5 {
        commits.push(commit_tx(i, COMMIT_TICK + 1, &commit_item(query_id(), MESSAGE, i as u16)));
    }
    commits.push(good_commit(3));
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn commit_tick_not_after_query_tick_not_counted() {
    let mut commits = good_commits(10);
    for i in 10..15 {
        commits.push(commit_tx(i, QUERY_TICK, &commit_item(query_id(), MESSAGE, i as u16)));
    }
    commits.push(commit_tx(15, QUERY_TICK - 1, &commit_item(query_id(), MESSAGE, 15)));
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn malformed_commit_not_counted() {
    let mut commits = good_commits(10);
    let mut wrong_type = good_commit(10);
    wrong_type[76] = 7; // inputType 7 (sig now invalid too)
    commits.push(wrong_type);
    let mut truncated = good_commit(11);
    truncated.pop();
    commits.push(truncated);
    commits.push(Vec::new());
    commits.push(tx(&keys().computors[12], 1, COMMIT_TICK, 6, &commit_item(query_id(), MESSAGE, 12))); // amount
    commits.push(tx(&keys().user, 0, COMMIT_TICK, 6, &commit_item(query_id(), MESSAGE, 13))); // not a computor
    expect_quorum_fail(&fixture(commits), 10);
}

#[test]
fn reveal_input_mismatch_panics() {
    let mut fx = fixture(good_commits(0));
    let mut input = query_id().to_le_bytes().to_vec();
    input.extend_from_slice(b"Hello ZK, this is Qubic?");
    fx.reveal_tx = reveal_tx(&input);
    let err = execute(&fx).expect_err("guest must reject");
    assert!(err.contains("reveal tx: input != queryId | reply"), "{err}");
}

#[test]
fn query_tick_mismatch_panics() {
    let mut fx = fixture(good_commits(0));
    fx.query_id += 1 << 31;
    let err = execute(&fx).expect_err("guest must reject");
    assert!(err.contains("query tx: tick != queryId >> 31"), "{err}");
}

/// `cargo test --release -- --ignored write_fixtures`: Rust-side twin of crypto/build/gen_fixture.
#[test]
#[ignore]
fn write_fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/");
    fixture(good_commits(500)).save(std::path::Path::new(&format!("{dir}quorum_ok.bin"))).unwrap();
    let mut commits = good_commits(500);
    for c in &mut commits[300..] {
        let n = c.len();
        c[n - 64 + 7] ^= 0xff;
    }
    fixture(commits).save(std::path::Path::new(&format!("{dir}quorum_fail.bin"))).unwrap();
}
