# ZKProofDemo

Prove on Ethereum that **≥ 451 of Qubic's 676 computors committed to one oracle reply**, with one
RISC Zero Groth16 proof (~300 B, ~300k gas) instead of 451 FourQ signature checks on-chain.

```
Qubic side                          this repo                                   Ethereum
──────────                          ─────────                                   ────────
arbitrator-signed computor list ─┐  guest program (RISC Zero zkVM)              QubicQuorumVerifier
+ query tx, ≥451 commit txs,     ┼─▶ re-verifies every tx in C,   ──▶ STARK ──▶ Groth16 ──▶ attest(journal, seal)
+ reveal tx (the reply)          ┘  journal = epoch | queryId | K12(reply)        (GPU farm)     → isAttested(digest, epoch)
```

## How the demo works

1. 676 devnet computor seeds + arbitrator seed `z`×55 live in `crypto/seeds/` (public test keys).
2. `gen_fixture` (C) builds the Qubic oracle round: query tx, 500 commit txs, reveal tx, signed computor list.
3. The zkVM guest checks the arbitrator signature over the list; epoch ≠ 0; no duplicate pubkey.
4. It checks the query and reveal transactions and derives `D = K12(reply)`.
5. It counts commit txs: valid signature, distinct list member, item `{queryId, D, K12(reply‖index)}`.
6. Fewer than 451 valid commits ⇒ `panic!` ⇒ no proof can exist (`fixtures/quorum_fail.bin`).
7. Otherwise it commits a 44-byte journal: `epoch u32 | queryId u64 | D`.
8. A bento GPU farm proves the run and wraps it into a Groth16 seal (~5 min, 4 GPUs).
9. `attest(journal, seal)`: the RISC Zero router verifies the seal under the immutable `IMAGE_ID`.
10. The contract records `isAttested[D][epoch]` and `attestedQueryId`; consumers recompute `K12(reply)`.
11. The arbitrator pubkey is baked into `IMAGE_ID`: a different guest or key cannot produce a valid seal.

## Documents

| Read | To learn |
|---|---|
| [`SPEC.md`](SPEC.md) | Normative byte layouts: computor packet, transactions, fixture `ZKQFIX02`, journal, guest statement, contract ABI. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Data flow diagram from seeds to `attest`, wire-format table, trust model (what is and is not proved). |
| [`SECURITY.md`](SECURITY.md) | Exact security claim, consumer obligations, trust roots, operational rules, vulnerability reporting. |
| [`docs/GROTH16_NO_CEREMONY.md`](docs/GROTH16_NO_CEREMONY.md) | Why no trusted setup is needed: RISC Zero's universal wrapper, `IMAGE_ID` as program identity. |
| [`docs/RUST_TO_C.md`](docs/RUST_TO_C.md) | How the C crypto is linked into the rv32im guest, the two load-bearing gcc flags, bigint2 acceleration. |
| [`crypto/README.md`](crypto/README.md) | The C library: reference vs portable port, Makefile targets, differential tests, licenses. |
| [`methods/README.md`](methods/README.md) | The guest program: statement, input frames, build script. |
| [`host/README.md`](host/README.md) | Host tools: `zkq-prove`, `run_fixture`, `image_id`; `proof.json` format; Rust tests. |
| [`fixtures/README.md`](fixtures/README.md) | The committed demo inputs and the real Groth16 receipt; how to regenerate them. |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | `config/deploy.env` keys, deploy/verify runbook, mainnet checklist. |
| [`docs/BENTO.md`](docs/BENTO.md) | Running the GPU proving farm: build, server, workers, sizing, version lock, troubleshooting. |
| [`docker/README.md`](docker/README.md) | Pinned dev image and the containerised farm variant. |
| [`docs/E2E_REPORT.md`](docs/E2E_REPORT.md) | Evidence: real proof, Sepolia transactions, tamper checks, gates, history of IMAGE_IDs. |

## Reproduce from scratch (fresh Ubuntu 24.04)

**1. Toolchain.** Either the pinned image or native:
```bash
git clone https://github.com/qubic/ZKProofDemo && cd ZKProofDemo
docker build -f docker/Dockerfile.dev -t zkq-dev . && docker run --rm -it -v "$PWD:/work" zkq-dev
```
```bash
# native: gcc/make/python3, Rust 1.96.1 (rust-toolchain.toml), RISC Zero, Foundry
sudo apt install -y build-essential python3 git curl pkg-config libssl-dev
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.96.1 --component rust-src
curl -L https://risczero.com/install | bash && rzup install rust 1.94.1 && rzup install cpp 2024.1.5 && rzup install r0vm 3.0.4
curl -L https://foundry.paradigm.xyz | bash && foundryup -i v1.7.1
```

**2. Crypto self-test.** Portable port vs Qubic reference, native.
```bash
crypto/tests/run_tests.sh            # RESULT: ALL PASS
```

**3. Build and generate inputs.**
```bash
scripts/build.sh                     # cargo --locked, make crypto/, fixtures/quorum_{ok,fail}.bin, prints IMAGE_ID
```
Expected `IMAGE_ID: 0x77948aba14eefc52875e6f06ff4642f07b0b1a1095394e66fbf38294912fd9ac` (risc0 3.0.4).

**4. Execute the guest without proving.**
```bash
RISC0_DEV_MODE=1 target/release/run_fixture                       # PASS quorum_ok.bin ... quorum_fail.bin panics
RISC0_DEV_MODE=1 cargo test --release --locked
target/release/zkq-prove verify --proof fixtures/quorum_ok.groth16.json   # the committed real receipt
```

**5. Dev-mode demos** (fake receipts, no chain).
```bash
RISC0_DEV_MODE=1 scripts/demo_quorum_ok.sh
scripts/demo_quorum_fail.sh          # "quorum not reached: proof impossible"
```

**6. Sepolia signer.** Fund a key, then either a Foundry keystore or a file:
```bash
cast wallet import demo --interactive && sed -i 's/^ETH_ACCOUNT=.*/ETH_ACCOUNT=demo/' config/deploy.env
# or: echo "PRIVATE_KEY=0x..." > .wallet && chmod 600 .wallet
scripts/check_config.sh              # "== config OK" (bento WARNs are fine until step 8)
```

**7. Deploy the verifier.**
```bash
scripts/deploy_verifier.sh           # forge create contracts/QubicQuorumVerifier.sol (router, IMAGE_ID); writes VERIFIER=
```

**8. Proving farm.** One box with NVIDIA GPUs, per [`docs/BENTO.md`](docs/BENTO.md):
build bento at risc0 3.0.4, set `BENTO_AGENT` / `BENTO_REST_API` / `BONSAI_API_URL` in
`config/deploy.env`, `scripts/bento/start_server.sh`, `scripts/bento/status.sh` → `VERSION LOCK OK`.

**9. Real proof and on-chain attestation.**
```bash
RISC0_DEV_MODE=0 scripts/demo_quorum_ok.sh
#  receipt_kind: groth16 ... local verify OK
#  tx 0x…  isAttested(0x2a40…b827, 999) = true   attestedQueryId = 2147483648000000
RISC0_DEV_MODE=0 scripts/demo_quorum_fail.sh     # farm rejects it: "quorum not reached"
```

**10. Everything at once:** `scripts/e2e.sh` (steps 3–5 plus replay / wrong-digest fixtures; attests when `RISC0_DEV_MODE=0`).

## License

Apache-2.0 for this repository's own code ([`LICENSE`](LICENSE)). Qubic-core derived C is under
the Anti-Military License, FourQ tables under MIT, K12 parts CC0 — see [`NOTICE`](NOTICE).
