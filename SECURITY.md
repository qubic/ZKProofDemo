# Security

## What a valid proof states

A Groth16 receipt accepted by `QubicQuorumVerifier` for `imageId = IMAGE_ID` with journal
`epoch (u32 LE) | queryId (u64 LE) | K12(reply) (32 B)` proves exactly this, and nothing more:

1. The prover held a `Computors` packet (`epoch u16 | 676 pubkeys | sig`) whose SchnorrQ
   signature over `K12(packet[0..21634))` verifies under the arbitrator public key baked into
   the guest at build time (`config/deploy.env` → `methods/guest/build.rs` → `IMAGE_ID`).
2. A query transaction (inputType 10) signed by its source with `tick == queryId >> 31`, and a
   reveal transaction (inputType 7) signed by a list member carrying `queryId | reply`;
   `D = K12(reply)`.
3. At least 451 **distinct** members of that packet's pubkey list signed an `OracleReplyCommit`
   transaction (inputType 6, destination zero, amount 0, `tick >` query tick) whose input contains
   the item `{queryId, D, K12(reply ‖ computorIndex)}` — exactly what Qubic's oracle engine
   requires. 451 = ⌊2·676/3⌋ + 1, Qubic's own quorum; duplicates count once; a bad signature,
   another `queryId` or another digest is not counted; `epoch != 0`; no repeated pubkey. Because
   the signed bytes are full Qubic transactions, a commit cannot be confused with any other Qubic
   signature and cannot be replayed for another query.
4. The program that checked (1)–(3) is the one identified by `IMAGE_ID` (RISC Zero receipt claim
   binds `IMAGE_ID` and `sha256(journal)`).

## What is NOT proved — consumers must handle these

- **Reply meaning.** Only `K12(reply)` is committed; the guest does not parse the reply or query.
- **List uniqueness / arbitrator equivocation.** The arbitrator key could sign several lists for
  one epoch; the proof attests *a* list, not *the* list.
- **Freshness / liveness.** Signatures can be collected and proven any time later.
- **Epoch of a tick.** The guest takes the packet's epoch; it does not derive it from ticks.
  A consumer that cares should check `queryId >> 31` against the epoch's tick range.
- **Consumer context.** A consumer must bind the reply to itself (`chainId | consumer address |
  nonce | payload`) so a digest is meaningful in exactly one context, and must key its own state
  by `(digest, epoch)` as the contract does.
- No stake, no slashing, no Qubic ledger/tick state — signature validity only.

## Trust roots

| Root | Where | Notes |
|---|---|---|
| Arbitrator key | `config/deploy.env` → `IMAGE_ID` | Demo key is the public seed `z`×55 (`crypto/seeds/`); a real deployment must bake the live arbitrator identity and rotate `IMAGE_ID` when it changes. |
| RISC Zero verifier | `RiscZeroVerifierRouter` Sepolia `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187`, mainnet `0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319` | RISC Zero's Groth16 ceremony, the control root of the recursion circuit and the router's governance / emergency-stop (a stopped verifier rejects every seal). Not under this repo's control — `docs/GROTH16_NO_CEREMONY.md`. |
| C crypto port | `crypto/src/riscv_fourq_verify.c` | Differential-tested against the verbatim core reference `stock_qubic.c` (701 K12, 16 SchnorrQ, 677 keygen, 34 sign/verify vectors + ~30k tamper cases); bigint2 precompile results are host-supplied, so the guest range-checks every result `< p` and panics otherwise (`docs/RUST_TO_C.md`). |
| `IMAGE_ID` reproducibility | `rzup` rust 1.94.1, cpp 2024.1.5, risc0 3.0.4 crate set (`Cargo.lock`, `--locked`), fixed C flags | `build.rs` refuses foreign `CFLAGS`/`CC`. Same inputs → same `IMAGE_ID`; verify with `target/release/image_id` before trusting an on-chain allowlist entry. |

## Modes and operations

- `RISC0_DEV_MODE=1` produces **fake** receipts (no proof); they never verify on-chain and
  `zkq-prove verify` refuses them unless `--allow-fake`. Never set it in a real deploy.
- Bento farm and client must run the **same** risc0 (3.0.4); a mismatch fails loudly
  (`control_id mismatch`), it cannot produce a wrong-but-valid proof (`docs/BENTO.md`).
- Bento ports (8081 REST, 5432 postgres, 6379 redis, 9000 minio) are **unauthenticated**; firewall
  them to the farm LAN. `scripts/lib/config.sh` refuses the default infra credentials when
  `BENTO_INFRA_HOST` is not loopback.
- Signing key: prefer `ETH_ACCOUNT` (Foundry keystore) over a raw wallet file.
- Attestation is permissionless and unstaked: anyone with a valid proof may submit it.
- `crypto/seeds/` and `crypto/tests/vectors/keygen_vectors.txt` contain public devnet private keys;
  proofs built from them are meaningless outside a local devnet.
- Only the current `IMAGE_ID` (printed by `target/release/image_id`, built with risc0 3.0.4) is
  supported; older image IDs should be revoked from the allowlist.

## Reporting a vulnerability

Please contact our core team via Discord with a description and, if
possible, a fixture that reproduces it. Please do not open a public issue for exploitable
findings. We acknowledge within 7 days and aim to fix within 90 days, coordinating disclosure.
