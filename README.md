# ZKProofDemo
Demonstrate on how to generate a zk proof to transmit a authorized message from Computors to outside of qubic ecosystem

On this demo, we prove on Ethereum that **a quorum of Qubic computors (≥ 451 of 676) signed the message "Hello ZK, this is QUBIC."** — with one
Groth16 proof (~300 bytes, ~295k gas, about ~$1) instead of 451 FourQ signature checks on-chain, which is nearly impossible.

```
Qubic side                          this repo                                   Ethereum
──────────                          ─────────                                   ────────
arbitrator-signed computor list ─┐  guest program (RISC Zero zkVM)              QubicQuorumVerifier
+ ≥451 computor signatures ──────┼─▶ checks every signature in C,  ──▶ STARK ──▶ Groth16 ──▶ attest(journal, seal)
+ the message                    ┘  commits journal = epoch | digest              (GPU farm)     → isAttested(digest, epoch)
```

The zkVM program's hash (`IMAGE_ID`) is the only thing the contract trusts. The arbitrator's public
key is baked into that program, so the proof is bound to the real Qubic computor set. No trusted
setup of our own: RISC Zero's universal Groth16 circuit + its on-chain `RiscZeroVerifierRouter`.

---

## 1. Code structure

Four real components + support. Data flows crypto → guest → host → contract.

| Folder | Language | What it is | Why it exists |
|---|---|---|---|
| **`crypto/`** | C (+ C++ host shim) | FourQ **SchnorrQ verify** and **KangarooTwelve** (Qubic's hash), portable rv32im port `src/fourq_verify.c` + `tables.c`; `src/stock.c` = untouched Qubic-core reference used only as test oracle; `tools/derive_keys` (seed → pubkey/identity); `tests/` (vectors: 701 K12, 16 SchnorrQ, 677 keygen, 34 sign) | The zkVM is 32-bit RISC-V; Qubic's crypto had to be ported bit-exactly. Differentially tested against `stock.c` (0 diffs over ~90k adversarial cases). |
| **`methods/`** | Rust + the C above | The **guest** = the program being proven (`guest/src/main.rs`): read packet + query tx + reply + commit txs + reveal tx, verify the arbitrator signature, count ≥ 451 distinct valid commits, commit the 44-byte journal. `guest/src/bigint2.rs` moves field arithmetic onto risc0's `bigint2` precompile (597 M → 215 M cycles). `guest/build.rs` compiles `crypto/` into it and bakes the arbitrator from `config/deploy.env`. `src/lib.rs` exports `ZKQ_QUORUM_ELF` / `ZKQ_QUORUM_ID` (= IMAGE_ID). | Everything here changes IMAGE_ID. |
| **`host/`** | Rust | Native tools: `zkq-prove` (prove via a bento GPU farm; `verify` a receipt), `run_fixture` (execute the guest without proving), `image_id`, `zkq_identity`. `src/fixture.rs` = the `ZKQFIX02` input format. Test inputs come from `crypto/build/gen_fixture` (C). | Relayer/operator tooling; outputs `journal_hex` + `seal_hex` for the contract. |
| **`contracts/`** | Solidity | `QubicQuorumVerifier.sol` (single file, no framework): `attest(journal, seal)` → router verifies under the immutable `IMAGE_ID` → `isAttested[digest][epoch] = true`, `attestedQueryId[digest][epoch] = queryId`. | The on-chain consumer entry point. |
| `config/deploy.env` | — | **The one config**: profile, arbitrator identity, chain/router/verifier, signer, prover farm. Read by both build scripts and every shell script. | One place = no mismatch between guest, scripts and chain. |
| `scripts/` | bash | `build.sh` (locked build + fixtures), `check_config.sh`, `deploy_verifier.sh` (`forge create`), `demo_quorum_ok.sh`, `demo_quorum_fail.sh`, `e2e.sh`, `lib/config.sh`, `bento/` (GPU farm: server / workers / status / stop / cancel) | Operator entry points. |
| `crypto/seeds/` | text | 676 devnet computor seeds (public `core-lite` defaults) + arbitrator seed `z`×55 + derived pubkeys | Only so `gen_fixture` can sign test inputs. Never for production. |
| `fixtures/` | generated | `quorum_ok.bin`, `quorum_fail.bin`, receipts (`*.json`) — gitignored, see `fixtures/README.md` | Test inputs / evidence. |
| `docker/` | — | Pinned dev image (gcc, Rust, rzup, Foundry) + compose variant of the prover farm (untested) | Reproducible toolchain. |
| `docs/` | — | `DEPLOY.md` (runbook), `BENTO.md` (farm), `ARCHITECTURE.md`, `RUST_TO_C.md`, `GROTH16_NO_CEREMONY.md`, `E2E_REPORT.md` | |
| `SPEC.md`, `SECURITY.md`, `NOTICE` | — | Byte formats/constants; what is and is not proved; third-party licenses | |

If you only ever touch three things: `config/deploy.env` (deployment), `methods/guest/src/main.rs`
(the statement), `contracts/QubicQuorumVerifier.sol` (what the chain does with it).

### What exactly is proved (`SPEC.md`)

Inputs to the guest: `Computors` packet (`epoch u16 | 676 × pubkey 32 B | arbitrator sig 64 B`,
21 698 B), the oracle query tx, the reply, N `OracleReplyCommit` txs, the reveal tx.

1. The packet's signature verifies under the arbitrator pubkey baked into the guest.
2. The query tx is signed and `tick == queryId >> 31`; the reveal tx is signed by a list member and
   carries `queryId | reply`.
3. ≥ 451 **distinct** members of the list signed a commit tx (type 6) carrying
   `queryId | K12(reply) | K12(reply ‖ index)` — full Qubic transactions, so nothing can be replayed
   under another query or list.
4. Journal (public output, 44 B): `epoch u32 LE | queryId u64 LE | K12(reply)`.

The contract recomputes `sha256(journal)`, asks the RISC Zero router to verify the Groth16 seal
against the immutable `IMAGE_ID`, then stores `isAttested[digest][epoch] = true`. Consumers call
`isAttested(digest, epoch)`.

---

## 2. The demo, step by step

Everything runs from `config/deploy.env` (ships with devnet defaults: Sepolia, arbitrator = seed
`z`×55, prover farm on localhost).

**Step 0 — toolchain.** Either the dev image or local: Rust 1.96 (`rust-toolchain.toml`), `rzup`
with rust 1.94.1 + cpp 2024.1.5 + r0vm 3.0.4, gcc/make, Foundry.

```bash
docker build -f docker/Dockerfile.dev -t zkq-dev . && docker run --rm -it -v "$PWD:/work" zkq-dev
```

**Step 1 — crypto self-test.** Port vs Qubic reference.
```bash
crypto/tests/run_tests.sh          # K12 701/701, SchnorrQ 16/16, keygen 687/687, sign/verify 272/272
```

**Step 2 — build (locked) and read the program identity.**
```bash
scripts/build.sh
target/release/image_id            # IMAGE_ID + the arbitrator identity it was built with
```

**Step 3 — make the inputs.** 676 computors, epoch 999, reply `Hello ZK, this is Qubic!`;
500 of them send a commit tx (`gen_fixture` signs with the devnet seeds; `scripts/build.sh` already did this):
```bash
G="crypto/build/gen_fixture --seeds crypto/seeds/computor_seeds.txt --arbitrator-seed crypto/seeds/arbitrator_seed.txt --epoch 999 --message 'Hello ZK, this is Qubic!'"
$G --commits 500 --out fixtures/quorum_ok.bin
$G --commits 500 --bad-commits 200 --out fixtures/quorum_fail.bin     # 300 good + 200 corrupted signatures
```

**Step 4 — run the guest without proving (fast, dev mode).**
```bash
RISC0_DEV_MODE=1 target/release/run_fixture --fixture fixtures/quorum_ok.bin
#  PASS quorum_ok.bin: journal e7030000 0000000020a10700 2a40bd68…b827     ← epoch 999 | queryId | K12(reply)
RISC0_DEV_MODE=1 target/release/run_fixture --fixture fixtures/quorum_fail.bin --expect-fail
#  Guest panicked: quorum not reached: 300 valid distinct commits, need 451 ← no proof possible
```

**Step 5 — contract.** Validate the config, then deploy (IMAGE_ID is immutable: a new guest ⇒ a new contract):
```bash
scripts/check_config.sh            # chain id, router, signer, on-chain IMAGE_ID vs built, farm version lock → "== config OK"
scripts/deploy_verifier.sh         # deploys QubicQuorumVerifier(router, IMAGE_ID); writes VERIFIER= back
```

**Step 6 — real proof on GPUs and on-chain attestation.** Needs a bento farm (`docs/BENTO.md`).
```bash
RISC0_DEV_MODE=0 scripts/demo_quorum_ok.sh
#  prove …  receipt_kind: groth16, seal_hex 0x73c457ba…                 (~5 min on 4 × RTX 4090)
#  local verify OK under IMAGE_ID
#  tx 0x…   isAttested(0x2a40…b827, 999) = true   attestedQueryId = 2147483648000000
scripts/demo_quorum_fail.sh         # prover rejects the fail fixture: "quorum not reached: proof impossible"
```

`scripts/e2e.sh` runs steps 1–4, `cargo test`, the replay / wrong-digest fixtures, then both demos.

---

## 3. From demo to production

The demo already proves Qubic's real oracle flow: every computor's oracle machine sends an
`OracleReplyCommit` transaction (type 6) whose input carries `queryId | K12(reply) | knowledge proof`,
and the guest verifies those transactions byte-for-byte as core does:

```
Transaction (Qubic core network_messages/transactions.h)
  sourcePublicKey   32 B   ← the computor (must be in the epoch's list)
  destinationPublicKey 32 B
  amount            8 B
  tick              4 B   ← must be after the query tick
  inputType         2 B   ← 6 = OracleReplyCommit                            = domain separation
  inputSize         2 B
  input             n B   ← queryId u64 | replyDigest 32 B | knowledgeProof 32 B
  signature         64 B  ← SchnorrQ over K12(everything above)
```

What changes for production: the packet must be the live arbitrator-signed `BroadcastComputors`
(`ZKQ_ARBITRATOR_IDENTITY` = core's `ARBITRATOR`, new `IMAGE_ID`, new contract), and the fixture is
built from real network transactions instead of `gen_fixture`.

---

## 4. Use case: a Qubic → Ethereum bridge withdrawal

Goal: a user burns 100 wUSDT on Qubic and receives 100 USDT on Ethereum, with no trusted relayer.

1. **Qubic:** the user calls the bridge contract's `Withdraw(amount, ethRecipient)`. The contract
   burns the tokens and emits a log `Withdrawn(withdrawId, amount, ethRecipient)`.
2. **Oracle round:** anyone sends an oracle query for that log (`readQubicLog`, interface 4:
   `tick | txHash | logId`). Every computor's oracle machine reads its own bob node, builds the
   288-byte reply (the raw log), and broadcasts an `OracleReplyCommit` transaction with
   `K12(reply)`. ≥ 451 identical commits ⇒ the reply is revealed on Qubic.
3. **Relayer (permissionless):** collects the epoch's `BroadcastComputors` packet + 451 commit
   transactions for that `queryId`, writes a `ZKQFIX02` file, runs
   `zkq-prove --fixture … --mode groth16` on a GPU farm (~5 min), gets `journal` + `seal`.
4. **Ethereum:** the relayer calls `QubicQuorumVerifier.attest(journal, seal)` (~295k gas).
   The router verifies the Groth16 proof; the contract records `isAttested[replyDigest][epoch]`.
5. **Release:** the user (or relayer) calls `Bridge.release(reply bytes, epoch)`. The bridge contract
   computes `K12(reply)`, checks `verifier.isAttested(digest, epoch)`, decodes the reply
   (`emitter == Qubic bridge contract`, `logType == Withdrawn`, `withdrawId` unused), and transfers
   100 USDT to `ethRecipient`.

Why it is safe: releasing needs a valid proof that 451 of the 676 current computors — the same set
that runs Qubic consensus — committed to that exact log. A single relayer, a single RPC provider,
or the bridge operator cannot forge it; a wrong or missing quorum simply cannot be proven. Cost to
the user: one Groth16 verification (~$1 at 1 gwei / $3000 ETH) instead of 451 on-chain signature
checks (~$300+).

The same pipeline attests anything computors commit to: price feeds (oracle `readEVMLog` of a
Chainlink `AnswerUpdated` event, attested back to another chain), cross-chain messages, or proofs
of Qubic state for any EVM consumer.

---

## Zero-knowledge proof

The guest (`methods/guest`) re-verifies the whole oracle transaction series inside a RISC Zero
zkVM: arbitrator-signed computor list, query transaction, 451+ `OracleReplyCommit` transactions
(each SchnorrQ-signed, carrying `K12(reply)` and a knowledge proof), reveal transaction. Its
journal is 44 bytes: `epoch u32 | queryId u64 | K12(reply)`. The STARK is wrapped into a ~300-byte
Groth16 seal by RISC Zero's standard circuit — no trusted setup of our own; the program hash
(IMAGE_ID) identifies the exact verifier logic.

```bash
cargo build --release --locked                    # never `cargo update`: risc0 versions are pinned
target/release/image_id                           # IMAGE_ID + the arbitrator it was built with
RISC0_DEV_MODE=1 target/release/run_fixture --fixture fixtures/quorum_ok.bin    # execute, no proof
target/release/zkq-prove verify --proof fixtures/quorum_ok.groth16.json         # check the real receipt
# real proving needs a GPU farm: RISC0_DEV_MODE=0 BONSAI_API_URL=http://<bento>:8081 BONSAI_API_KEY=x \
#   target/release/zkq-prove --fixture fixtures/quorum_ok.bin --mode groth16 --out proof.json
```
