# Deployment runbook

One file drives everything: **`config/deploy.env`** (guest build, scripts, contract deploy).

```
config/deploy.env ─┬─ methods/guest/build.rs      arbitrator identity → pubkey → IMAGE_ID
                   ├─ scripts/check_config.sh     validates config vs chain, built guest, farm
                   ├─ scripts/deploy_verifier.sh  deploys QubicQuorumVerifier(router, IMAGE_ID)
                   ├─ scripts/bento/*.sh          prover farm
                   └─ scripts/demo_quorum_ok.sh   prove + attest
```

## 0. Edit `config/deploy.env`

| Key | Meaning | Mainnet |
|---|---|---|
| `ZKQ_PROFILE` | `devnet` / `mainnet` (mainnet: notices + typed confirmation before chain writes) | `mainnet` |
| `ZKQ_ARBITRATOR_IDENTITY` | 60-char arbitrator identity, **baked into IMAGE_ID** | `AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ` (core `public_settings.h`) |
| `ETH_CHAIN_ID` / `ETH_RPC` | target chain; RPC chain id is checked | `1` / your RPC |
| `RISC0_ROUTER` | RiscZeroVerifierRouter of that chain (risc0-ethereum `deployment.toml`) | `0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319` |
| `VERIFIER` | deployed `QubicQuorumVerifier`; empty ⇒ deploy and write back | (auto) |
| `ETH_ACCOUNT` / `WALLET_FILE` | signer: Foundry keystore name (preferred) or file with `PRIVATE_KEY=0x…`, mode 0600 | keystore |
| `BENTO_*`, `BONSAI_*`, `SEGMENT_PO2` | prover farm (`BENTO.md`) | your farm |

## 1. Build (locked)

```bash
scripts/build.sh                 # cargo build --release --locked; make crypto/; demo fixtures; prints IMAGE_ID
scripts/check_config.sh          # must end with "== config OK"
```
Never `cargo update`: `IMAGE_ID = f(guest code, risc0 crate set, arbitrator identity)`.

## 2. Verifier contract

```bash
scripts/deploy_verifier.sh
```
`VERIFIER` empty → `forge create contracts/QubicQuorumVerifier.sol` with `(RISC0_ROUTER, IMAGE_ID)`,
address written back to the config. `VERIFIER` set → checks `IMAGE_ID()` on chain equals the
build; on mismatch it exits 2: clear `VERIFIER=` and re-run (IMAGE_ID is immutable, so every
guest change is a new contract). Mainnet asks you to type `MAINNET` before the transaction.

## 3. Prover farm

`BENTO.md`: `scripts/bento/start_server.sh` on the infra box, `start_gpu_worker.sh` on each GPU
box, `status.sh` for health and the risc0 version lock.

## 4. Prove + attest

```bash
RISC0_DEV_MODE=0 scripts/demo_quorum_ok.sh        # fixture → Groth16 → verify → attest → isAttested / attestedQueryId
# any ZKQFIX02 fixture (e.g. relayer-supplied real epoch data):
RISC0_DEV_MODE=0 target/release/zkq-prove --fixture <f.bin> --mode groth16 --out proof.json
cast send $VERIFIER "attest(bytes,bytes)" <journal_hex> <seal_hex> --rpc-url $ETH_RPC --account <keystore>
```
`scripts/lib/config.sh` exports the config; an exported variable that differs from the file makes
every script refuse (the file is the truth: `unset` it or open a new shell).

## Mainnet checklist

1. Any guest, risc0 or arbitrator change ⇒ new `IMAGE_ID` ⇒ `deploy_verifier.sh` again (new address).
2. Verify `IMAGE_ID()` on chain after every deploy (`check_config.sh` does).
3. Build only with `scripts/build.sh`; bento agents must embed the same risc0 (`status.sh`).
4. The computors packet must be the live arbitrator-signed `BroadcastComputors` of the attested
   epoch; `gen_fixture` can only sign with the devnet arbitrator seed.
5. `(digest, epoch)` is attested once (re-attest is a no-op, the first `queryId` is kept).
