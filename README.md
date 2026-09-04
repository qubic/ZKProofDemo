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
| **`methods/`** | Rust + the C above | The **guest** = the program being proven (`guest/src/main.rs`): read packet + message + votes, verify the arbitrator signature, count ≥ 451 distinct valid computor signatures, commit the 36-byte journal. `guest/src/bigint2.rs` moves field arithmetic onto risc0's `bigint2` precompile (597 M → 203 M cycles). `guest/build.rs` compiles `crypto/` into it and bakes the arbitrator from `config/deploy.env`. `src/lib.rs` exports `ZKQ_QUORUM_ELF` / `ZKQ_QUORUM_ID` (= IMAGE_ID). | Everything here changes IMAGE_ID. |
| **`host/`** | Rust | Native tools: `zkq-prove` (prove via a bento GPU farm; `verify` a receipt), `gen_fixture` (build a test input from seeds), `run_fixture` (execute the guest without proving), `image_id`, `zkq_identity`. `src/fixture.rs` = the `ZKQFIX01` input format and the vote digest. | Relayer/operator tooling; outputs `journal_hex` + `seal_hex` for the contract. |
| **`contracts/`** | Solidity | `QubicQuorumVerifier.sol` (single file, no framework): `attest(journal, seal)` → router verifies under the immutable `IMAGE_ID` → `isAttested[digest][epoch] = true`, `attestedQueryId[digest][epoch] = queryId`. | The on-chain consumer entry point. |
| `config/deploy.env` | — | **The one config**: profile, arbitrator identity, chain/router/verifier, signer, prover farm. Read by both build scripts and every shell script. | One place = no mismatch between guest, scripts and chain. |
| `scripts/` | bash | `build.sh` (locked build), `check_config.sh`, `deploy_verifier.sh`, `demo_quorum_ok.sh`, `demo_quorum_fail.sh`, `e2e.sh`, `lib/config.sh`, `bento/` (GPU farm: start server / GPU workers / status / stop / cancel) | Operator entry points. |
| `seeds/` | text | 676 devnet computor seeds (public `core-lite` defaults) + arbitrator seed `z`×55 + derived pubkeys | Only so `gen_fixture` can sign test inputs. Never for production. |
| `fixtures/` | generated | `quorum_ok.bin`, `quorum_fail.bin`, receipts (`*.json`) — gitignored, see `fixtures/README.md` | Test inputs / evidence. |
| `docker/` | — | Pinned dev image (gcc, Rust, rzup, Foundry) + an untested compose variant of the prover farm | Reproducible toolchain. |
| `docs/` | — | `DEPLOY.md` (runbook), `BENTO.md` (farm), `ARCHITECTURE.md`, `RUST_TO_C.md`, `GROTH16_NO_CEREMONY.md`, `E2E_REPORT.md` | |
| `SPEC.md`, `SECURITY.md`, `NOTICE` | — | Byte formats/constants; what is and is not proved; third-party licenses | |

If you only ever touch three things: `config/deploy.env` (deployment), `methods/guest/src/main.rs`
(the statement), `contracts/QubicQuorumVerifier.sol` (what the chain does with it).

### What exactly is proved (`SPEC.md`)

Inputs to the guest: `Computors` packet (`epoch u16 | 676 × pubkey 32 B | arbitrator sig 64 B`,
21 698 B), the message bytes, and N votes (`computorIndex u16 | SchnorrQ sig 64 B`).

1. The packet's signature verifies under the arbitrator pubkey baked into the guest.
2. ≥ 451 **distinct** indices of that list have a valid signature over
   `voteDigest = K12(VOTE_DOMAIN | epoch | K12(message))` — bound to this protocol and this epoch, so
   a vote can never double as a Qubic transaction/tick signature nor be replayed under another list.
3. Journal (public output, 36 B): `epoch u32 LE | K12(message)`.

The contract recomputes `sha256(journal)`, asks the RISC Zero router to verify the Groth16 seal
against the immutable `IMAGE_ID`, then stores `isAttested[digest][epoch] = true`. Consumers call
`isAttested(digest, epoch)`.

---

## 2. The demo, step by step

Everything runs from `config/deploy.env` (ships with devnet defaults: Sepolia, arbitrator = seed
`z`×55, prover farm on localhost).

**Step 0 — toolchain.** Either the dev image or local: Rust 1.96 (`rust-toolchain.toml`), `rzup`
with rust 1.94.1 + cpp 2024.1.5 + r0vm 3.0.4, cmake/gcc, Foundry.

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

**Step 3 — make the inputs.** 676 computors, epoch 999, message `Hello ZK, this is QUBIC.`;
500 of them sign the vote digest (`gen_fixture` signs with the devnet seeds):
```bash
target/release/gen_fixture --seeds seeds/computor_seeds.txt --arbitrator-seed seeds/arbitrator_seed.txt \
    --epoch 999 --message "Hello ZK, this is QUBIC." --votes 500 --out fixtures/quorum_ok.bin
target/release/gen_fixture ... --votes 500 --bad-votes 200 --out fixtures/quorum_fail.bin   # 300 good + 200 corrupted
```

**Step 4 — run the guest without proving (fast, dev mode).**
```bash
RISC0_DEV_MODE=1 target/release/run_fixture --fixture fixtures/quorum_ok.bin
#  PASS quorum_ok.bin: journal e7030000 c40f7721…e405e1 (203 M cycles)      ← epoch 999 | K12(message)
RISC0_DEV_MODE=1 target/release/run_fixture --fixture fixtures/quorum_fail.bin --expect-fail
#  Guest panicked: quorum not reached: 300 valid distinct votes, need 451   ← no proof possible
```

**Step 5 — contract.** Validate the config, then deploy (or sync the image on an existing verifier):
```bash
scripts/check_config.sh            # chain id, router, signer, IMAGE_ID vs on-chain, farm version lock → "== config OK"
scripts/deploy_verifier.sh         # deploys QubicQuorumVerifier(router, IMAGE_ID); writes VERIFIER= back
```

**Step 6 — real proof on GPUs and on-chain attestation.** Needs a bento farm (`docs/BENTO.md`).
```bash
RISC0_DEV_MODE=0 scripts/demo_quorum_ok.sh
#  prove …  receipt_kind: groth16, seal_hex 0x73c457ba…                 (~5 min on 4 × RTX 4090)
#  local verify OK under IMAGE_ID
#  attest tx 0x…   isAttested(0xc40f…e405e1, 999) = true
scripts/demo_quorum_fail.sh         # prover rejects the fail fixture: "quorum not reached: proof impossible"
```

`scripts/e2e.sh` runs steps 1–4 plus a replay check (votes signed for epoch 998 under the
epoch-999 list → 0 valid votes).

---

## 3. From demo to production

The demo proves a quorum over an **arbitrary message**. In production the computors do not sign
loose messages — they sign **transactions**, and the thing to prove is "≥ 451 computors broadcast a
transaction carrying X". Concretely, Qubic's oracle machine makes every computor send an
`OracleReplyCommit` transaction (type 6) whose input contains `queryId | K12(reply) | knowledge proof`.
That transaction already carries everything the demo's vote digest had to add by hand:

```
Transaction (Qubic core network_messages/transactions.h)
  sourcePublicKey   32 B   ← the computor (must be in the epoch's list)   = the "vote index"
  destinationPublicKey 32 B
  amount            8 B
  tick              4 B   ← when                                            (epoch = f(tick))
  inputType         2 B   ← 6 = OracleReplyCommit                            = domain separation
  inputSize         2 B
  input             n B   ← queryId u64 | replyDigest 32 B | knowledgeProof 32 B
  signature         64 B  ← SchnorrQ over K12(everything above)
```

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
   transactions for that `queryId`, writes a `ZKQFIX01` file, runs
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
