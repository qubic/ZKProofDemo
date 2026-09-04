# methods/ — RISC Zero guest `zkq-quorum`

`methods/guest` is the zkVM program; `methods/build.rs` runs `risc0_build::embed_methods()` and
`methods/src/lib.rs` exposes the generated constants, named after the guest **package**
(`zkq-quorum`): `ZKQ_QUORUM_ELF` (guest binary) and `ZKQ_QUORUM_ID` (image ID = program identity
checked on-chain; print with `target/release/image_id`).

## Statement (`guest/src/main.rs`, see `../SPEC.md`)

1. `fourq_verify(ARBITRATOR_PUBKEY, packet.sig, K12(packet[..21634]))`; `epoch != 0`; no repeated
   pubkey. The arbitrator pubkey comes from `config/deploy.env` (decoded in `guest/build.rs`) and
   is baked into the image ID.
2. Query tx: length `== 80 + inputSize + 64`, inputType 10, destination zero, SchnorrQ(source)
   over `K12(tx[..len-64])` valid, `tick == queryId >> 31`.
3. Reveal tx: inputType 7, destination zero, amount 0, source ∈ list, signature valid,
   input `== queryId u64 LE | reply`.
4. Commit txs, counted only if: well-formed, inputType 6, destination zero, amount 0,
   `tick > query tick`, source ∈ list at index `i` not yet counted, some 72-B item
   `== queryId | K12(reply) | K12(reply ‖ i u16 LE)`, signature valid. Stops at 451; otherwise
   `panic!("quorum not reached: …")` — a panic aborts proving, so no receipt can exist.
   Malformed commits are skipped, never fatal.
5. `env::commit_slice(epoch u32 LE | queryId u64 LE | K12(reply))` — 44-byte journal, packed
   bytes so the contract can recompute `sha256(journal)`.

## Inputs (positional frames `len u32 LE | bytes`, host `write_frame` order — `host/src/fixture.rs::to_env`)

| # | name | frame payload | size |
|---|------|------|------|
| 1 | `computors_packet` | bytes | 21698: `epoch u16 \| 676 × pubkey 32 \| arbitrator sig 64` |
| 2 | `query_id` | u64 LE | 8 |
| 3 | `query_tx` | raw Qubic transaction | 80 + inputSize + 64 |
| 4 | `reply` | bytes | 1..1008 |
| 5 | `commit_txs` | `n u32 \| n × (len u32 \| tx bytes)` | variable |
| 6 | `reveal_tx` | raw Qubic transaction | 80 + inputSize + 64 |

Frames are read with two `read_slice` syscalls each (a serde `Vec<u8>` cost 8 M cycles).

## How the C is linked (`guest/build.rs`)

The `cc` crate compiles `../../crypto/src/{riscv_fourq_verify.c,riscv_tables.c}` into the
guest with `-O3 -fno-strict-aliasing -fsigned-char` — both `-f` flags are load-bearing
(`../crypto/README.md`). risc0-build sets `CC` to rzup's
`riscv32-unknown-elf-gcc` (`rzup install cpp`), so the C is built by gcc, not clang. The guest
declares `fourq_verify` and `qubic_k12` by hand; buffers passed to C are 8-byte aligned
(`#[repr(align(8))]`). `build.rs` also defines `ZKQ_BIGINT2`: field arithmetic calls the
`zkq_*` shims in `guest/src/bigint2.rs` (risc0 bigint2 precompile; ≈215 M cycles for the
500-commit fixture). A second guest bin, `guest/src/bin/zkq_vectors.rs` (`ZKQ_VECTORS_ELF`),
runs the 16 SchnorrQ vectors on-target: `run_fixture --vectors`.

## Build / run

```bash
cargo build --release                                   # from the project root (workspace)
RISC0_DEV_MODE=1 target/release/run_fixture             # execute guest on both fixtures, no proof
cargo test --release --locked                           # incl. host/tests/guest_quorum.rs
```

Any change to the guest source, the C sources or the risc0 version changes `ZKQ_QUORUM_ID`;
a new `QubicQuorumVerifier` must then be deployed with the new `IMAGE_ID` (it is immutable).
