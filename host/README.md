# host/ — fixture parsing, proving, verification

Library (`src/fixture.rs`, `src/crypto.rs`) + four binaries, built into `target/release/` by
`cargo build --release` at the project root. Fixtures come from `crypto/build/gen_fixture`
(`../fixtures/README.md`).

| binary | purpose |
|--------|---------|
| `run_fixture` | execute the guest (no proof), assert journal / `quorum not reached` panic |
| `zkq-prove` | prove a fixture → `proof.json`; `zkq-prove verify --proof proof.json` |
| `image_id` | print `ZKQ_QUORUM_ID` as bytes32 hex (contract `IMAGE_ID`) |
| `zkq_identity` | Qubic identity ⇄ pubkey helper |

## Fixture `ZKQFIX02` (`src/fixture.rs`)

`"ZKQFIX02" | computorsPacket 21698 | queryId u64 | qLen u32 | queryTx | rLen u32 | reply
| n u32 | n × (len u32 | commitTx) | vLen u32 | revealTx`, little-endian (`SPEC.md` "Wire formats").
`Fixture::parse` bounds-checks every field and rejects trailing bytes. `Fixture::to_env` writes six
`write_frame`s in the exact positional order the guest reads (`../methods/README.md`).
Journal (`JOURNAL_SIZE` = 44): `epoch u32 LE | queryId u64 LE | K12(reply)`.

## Prove / verify
```bash
B=target/release
RISC0_DEV_MODE=1 $B/run_fixture                                                    # both demo fixtures
RISC0_DEV_MODE=1 $B/run_fixture --fixture fixtures/quorum_replay.bin --expect-fail
RISC0_DEV_MODE=1 $B/zkq-prove --fixture fixtures/quorum_ok.bin --out proof.json    # fake receipt, fast
$B/zkq-prove --fixture fixtures/quorum_ok.bin --out proof.json --mode groth16      # needs docker (risc0-groth16-prover)
BONSAI_API_URL=http://<bento>:8081 BONSAI_API_KEY=x $B/zkq-prove ... --mode groth16  # bento farm
RISC0_DEV_MODE=1 $B/zkq-prove verify --proof proof.json                            # receipt.verify(IMAGE_ID)
```
`--mode` is `groth16` (default; on-chain seal), `succinct` or `composite`. `proof.json`:
`{image_id, journal_hex, seal_hex, receipt_kind, receipt}` — `seal_hex` is 4-byte verifier
selector ‖ Groth16 seal, i.e. the `seal` argument of `QubicQuorumVerifier.attest`.

`build.rs` runs `make` on `../crypto` and links `libstock_qubic.a` + `libriscv_qubic.a` (+ `stdc++`);
`src/crypto.rs` wraps the six functions of `crypto/include/riscv_qubic_crypto.h` + `stock_host.h`.

## Tests — `cargo test --release`

`src/fixture.rs`: round-trip, malformed/truncated input, journal layout. `tests/crypto_vectors.rs`:
all `crypto/tests/vectors/` through the native FFI. `tests/guest_quorum.rs`: builds SPEC fixtures
from `crypto/seeds/` in Rust and executes the guest — 500 commits → 44-B journal; corrupted / wrong-digest /
wrong-queryId / duplicate / tick-order commits not counted; reveal or query mismatch → panic.
`-- --ignored write_fixtures` writes fixtures byte-identical to the C generator's.

## IMAGE_ID
Current build (risc0 3.0.4): `0x77948aba14eefc52875e6f06ff4642f07b0b1a1095394e66fbf38294912fd9ac`
— reproduce with `target/release/image_id`.
