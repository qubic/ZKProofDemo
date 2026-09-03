# seeds/ — DEVNET TEST KEYS ONLY

`computor_seeds.txt`: the 676 default computor seeds of `qubic/core-lite` (`private_settings.h`,
public upstream). `arbitrator_seed.txt`: `z`×55. `*_pubkey*.txt`: derived with `crypto/tools/derive_keys`
(`seed pubkey_hex identity` per line), used by tests and `scripts/check_config.sh`.

These keys are public. Anyone can sign with them. They exist so `gen_fixture` can build test inputs.
Never use them for anything but a local devnet; mainnet proofs use the live arbitrator/computors.

`crypto/tests/vectors/keygen_vectors.txt` also contains the derived subseeds and private keys of
these public devnet seeds (columns `subseedHex privHex`) — test vectors, equally public.
