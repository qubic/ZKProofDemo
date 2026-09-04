//! Executes the guest (no proof) against fixtures and asserts the outcome; fast CI check.

//! Default: quorum_ok.bin must commit the exact 44-byte journal; quorum_fail.bin must panic "quorum not reached".

//! --vectors runs the 16 SchnorrQ vectors inside the guest.
use host::fixture::{decode_journal, Fixture, JOURNAL_SIZE};
use host::hex;
use methods::{ZKQ_QUORUM_ELF, ZKQ_VECTORS_ELF};
use risc0_zkvm::{default_executor, ExecutorEnv};
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures"))
}

fn run(path: &Path, expect_fail: bool) {
    let fx = Fixture::load(path).unwrap_or_else(|e| {
        eprintln!("{e}\nHint: generate fixtures first (scripts/build.sh or crypto/build/gen_fixture).");
        std::process::exit(1);
    });
    let name = path.file_name().unwrap().to_string_lossy();
    println!("{name}: epoch {}, queryId {}, {} commits, executing...", fx.epoch(), fx.query_id, fx.commit_count());
    match default_executor().execute(fx.to_env(), ZKQ_QUORUM_ELF) {
        Ok(info) => {
            assert!(!expect_fail, "FAIL {name}: guest accepted a fixture that must be rejected");
            let journal = &info.journal.bytes;
            assert_eq!(journal.len(), JOURNAL_SIZE, "{name}: journal size");
            assert_eq!(journal[..], fx.expected_journal()[..], "{name}: journal bytes");
            println!("PASS {name}: journal {} ({} cycles)", hex(journal), info.cycles());
            let (epoch, query_id, digest) = decode_journal(journal);
            println!("  epoch:   {epoch}");
            println!("  queryId: {query_id}");
            println!("  digest:  {}", hex(digest));
        }
        Err(e) => {
            let first = e.to_string().lines().next().unwrap_or_default().to_string();
            assert!(expect_fail, "FAIL {name}: guest panicked but must succeed: {first}");
            assert!(first.contains("quorum not reached"), "FAIL {name}: rejected for the wrong reason: {first}");
            println!("PASS {name}: guest rejected as expected");
            println!("  guest error: {first}");
        }
    }
}

/// Executes the zkq-vectors guest on crypto/tests/vectors/schnorrq_vectors.txt.
fn run_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../crypto/tests/vectors/schnorrq_vectors.txt");
    let text = std::fs::read_to_string(path).expect("vectors missing: run crypto/tests/run_tests.sh");
    let mut records = Vec::new();
    let mut n = 0u32;
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        for h in &f[1..4] {
            records.extend(hex::decode(h).unwrap());
        }
        records.push(u8::from(f[0] == "1"));
        n += 1;
    }
    let env = ExecutorEnv::builder().write_frame(&records).build().unwrap();
    let info = default_executor().execute(env, ZKQ_VECTORS_ELF).expect("guest rejected a vector");
    assert_eq!(info.journal.bytes, n.to_le_bytes(), "vector count journal");
    println!("PASS schnorrq_vectors.txt in guest: {n} vectors ({} cycles)", info.cycles());
}

fn main() {
    let mut fixture: Option<PathBuf> = None;
    let mut expect_fail = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--fixture" => fixture = Some(args.next().expect("--fixture needs a path").into()),
            "--expect-fail" => expect_fail = true,
            "--vectors" => return run_vectors(),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    match fixture {
        Some(p) => run(&p, expect_fail),
        None => {
            run(&fixtures_dir().join("quorum_ok.bin"), false);
            run(&fixtures_dir().join("quorum_fail.bin"), true);
        }
    }
    println!("All fixtures behaved as asserted.");
}
