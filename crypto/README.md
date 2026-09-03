# crypto/ — FourQ/SchnorrQ + KangarooTwelve + Qubic keygen (C)

Self-contained C library: Qubic KangarooTwelve + FourQ SchnorrQ. The split:

| Role | Files | API |
|---|---|---|
| Prover (RISC Zero guest) needs only these | `src/riscv_fourq_verify.c` `src/riscv_tables.c` `include/riscv_qubic_crypto.h` | `qubic_k12`, `fourq_verify` |
| Host-side tooling (signing, keygen, test oracle) | `src/stock_qubic.c` `src/stock_host.cpp` `src/stock_shim.hpp` `include/stock_host.h` | `qubic_seed_to_subseed`, `qubic_subseed_to_keys`, `qubic_sign`, `qubic_identity` |

`stock_qubic.c` is the Qubic-core reference (verbatim; the Makefile patches one `__m256i ==`
line for g++). `riscv_fourq_verify.c` is its portable rv32im port (C11 + `uint64_t`, no
intrinsics). The host functions stay: `tools/gen_fixture.c` signs demo transactions,
`tools/derive_keys.c` derives pubkeys/identities, `tests/check_keys.c` /
`tests/check_roundtrip.cpp` test them.

## Build (plain Makefile, outputs under `build/`)

```
make all     # build/libriscv_qubic.a, build/libstock_qubic.a, gen_fixture, check_fixture, derive_keys
make tests   # check_port, check_k12, check_keys, check_roundtrip, gen_vectors
make test    # runs tests/run_tests.sh (expects RESULT: ALL PASS)
make clean
```

Mandatory prover flags (reproduce in any other build, e.g. the guest `cc::Build`):
`-fno-strict-aliasing` (the port type-puns through pointers; gcc miscompiles it otherwise) and
`-fsigned-char` (wNAF digits are signed `char`; RISC-V gcc defaults `char` to unsigned).
In-source: `KangarooTwelve_F.state` is `aligned(8)`. Host lib flags: `-O2 -mavx2 -mbmi -mbmi2 -madx`.

## Tests and tools

`tests/run_tests.sh` builds everything, regenerates `tests/vectors/*.txt` from the
`stock_qubic.c` oracle, runs all check binaries, diffs `derive_keys` output against
`seeds/*.txt`, and smoke-tests `gen_fixture`/`check_fixture` (good fixture accepted,
`--bad-commits 1` rejected). `tools/gen_fixture.c` writes `ZKQFIX02` oracle fixtures
(layout documented in `tools/gen_fixture.c`); every signature is re-verified with `fourq_verify` before writing.

## License

`riscv_fourq_verify.c`, `stock_qubic.c`, `stock_shim.hpp`, `stock_host.cpp`: Qubic core derived,
Anti-Military License (`LICENSE-QUBIC.md`). `riscv_tables.c`: MSR FourQlib, MIT
(`LICENSE-FourQlib.md`). KangarooTwelve parts derive from XKCP (CC0). See `../NOTICE`.
