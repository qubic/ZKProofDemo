//! zkq-prove: prove a ZKQFIX02 fixture and export journal + EVM seal, or verify a proof.

//! Prover via risc0 `default_prover()`: RISC0_DEV_MODE=1 fake, BONSAI_* remote, else local CPU.

//! `seal_hex` is `encode_seal` output for groth16/dev receipts, empty for STARK receipts.
use host::fixture::{decode_journal, Fixture, JOURNAL_SIZE};
use host::hex;
use methods::{ZKQ_QUORUM_ELF, ZKQ_QUORUM_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, InnerReceipt, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Proof {
    image_id: String,
    journal_hex: String,
    seal_hex: String,
    receipt_kind: String,
    receipt: Receipt,
}

fn image_id_hex() -> String {
    format!("0x{}", Digest::from(ZKQ_QUORUM_ID))
}

fn receipt_kind(r: &Receipt) -> &'static str {
    match &r.inner {
        InnerReceipt::Fake(_) => "fake",
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Groth16(_) => "groth16",
        _ => "other",
    }
}

fn prove(fixture: &Path, out: &Path, mode: &str) {
    let fx = Fixture::load(fixture).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let opts = match mode {
        "groth16" => ProverOpts::groth16(),
        "succinct" => ProverOpts::succinct(),
        "composite" => ProverOpts::composite(),
        other => panic!("unknown --mode {other} (groth16|succinct|composite)"),
    };
    println!(
        "fixture {}: epoch {}, queryId {}, {} commits; proving (mode {mode})...",
        fixture.display(),
        fx.epoch(),
        fx.query_id,
        fx.commit_count()
    );
    let receipt = default_prover()
        .prove_with_opts(fx.to_env(), ZKQ_QUORUM_ELF, &opts)
        .expect("proving failed (guest panicked or prover error)")
        .receipt;
    receipt.verify(ZKQ_QUORUM_ID).expect("receipt verification failed");
    let journal = &receipt.journal.bytes;
    assert_eq!(journal.len(), JOURNAL_SIZE, "unexpected journal size");
    assert_eq!(journal[..], fx.expected_journal()[..], "journal mismatch");

    let proof = Proof {
        image_id: image_id_hex(),
        journal_hex: format!("0x{}", hex(journal)),
        seal_hex: encode_seal(&receipt).map(|s| format!("0x{}", hex(s))).unwrap_or_default(),
        receipt_kind: receipt_kind(&receipt).into(),
        receipt,
    };
    std::fs::write(out, serde_json::to_vec_pretty(&proof).unwrap()).expect("writing --out");
    println!("image_id:     {}", proof.image_id);
    println!("journal_hex:  {}", proof.journal_hex);
    println!("seal_hex:     {}", proof.seal_hex);
    println!("receipt_kind: {}", proof.receipt_kind);
    println!("wrote {}", out.display());
}

fn verify(proof_path: &Path, allow_fake: bool) {
    let bytes = std::fs::read(proof_path).expect("cannot read --proof");
    let proof: Proof = serde_json::from_slice(&bytes).expect("malformed proof.json");
    assert_eq!(proof.image_id, image_id_hex(), "proof image_id != this build's IMAGE_ID");
    let kind = receipt_kind(&proof.receipt);
    // Dev-mode (Fake) receipts verify trivially under RISC0_DEV_MODE=1: never trust them by default.
    assert!(allow_fake || kind != "fake", "FAKE (dev-mode) receipt: not a proof (--allow-fake to inspect)");
    proof.receipt.verify(ZKQ_QUORUM_ID).expect("receipt verification FAILED");
    let journal = &proof.receipt.journal.bytes;
    assert_eq!(journal.len(), JOURNAL_SIZE, "journal size");
    assert_eq!(format!("0x{}", hex(journal)), proof.journal_hex, "journal_hex mismatch");
    assert_eq!(kind, proof.receipt_kind, "receipt_kind field mismatch");
    let seal = encode_seal(&proof.receipt).map(|s| format!("0x{}", hex(s))).unwrap_or_default();
    assert_eq!(seal, proof.seal_hex, "seal_hex field mismatch");
    println!("OK: {} receipt verifies under image_id {}", kind, proof.image_id);
    let (epoch, query_id, digest) = decode_journal(journal);
    println!("  epoch:   {epoch}");
    println!("  queryId: {query_id}");
    println!("  digest:  {}", hex(digest));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("verify") {
        let mut proof = PathBuf::from("proof.json");
        let mut allow_fake = false;
        let mut it = args[1..].iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--proof" => proof = it.next().expect("--proof needs a path").into(),
                "--allow-fake" => allow_fake = true,
                other => panic!("unknown argument: {other}"),
            }
        }
        return verify(&proof, allow_fake);
    }
    let mut fixture = PathBuf::from("fixtures/quorum_ok.bin");
    let mut out = PathBuf::from("proof.json");
    let mut mode = String::from("groth16");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| panic!("{a} needs a value")).clone();
        match a.as_str() {
            "--fixture" => fixture = val().into(),
            "--out" => out = val().into(),
            "--mode" => mode = val(),
            other => {
                eprintln!("unknown argument: {other}\nusage: zkq-prove [--fixture <bin>] [--out proof.json] [--mode groth16|succinct|composite] | zkq-prove verify --proof proof.json");
                std::process::exit(2);
            }
        }
    }
    prove(&fixture, &out, &mode);
}
