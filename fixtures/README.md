# fixtures/ — pre-generated demo inputs and the real proof

Committed so the demo works out of the box. Everything is reproducible; commands below.

| File | What | How it behaves |
|---|---|---|
| `quorum_ok.bin` (132 106 B) | `ZKQFIX02`: computors packet (epoch 999) + query tx + **500 valid** `OracleReplyCommit` txs + reveal tx; reply = `Hello ZK, this is Qubic!` | guest accepts, journal `e7030000 \| 0000000020a10700 \| 2a40bd68…4121b827` |
| `quorum_fail.bin` | 300 valid + **200 corrupted-signature** commits | guest panics: `quorum not reached: 300 valid distinct commits, need 451` |
| `quorum_wrongdigest.bin` | 300 valid + 200 commits to **another digest** | rejected (300/451) |
| `quorum_replay.bin` | all commits carry **another queryId** | rejected (0/451) |
| `quorum_ok.groth16.json` | the **real Groth16 receipt** of `quorum_ok.bin` (journal + seal + full risc0 receipt), attested on Sepolia (verifier `0xcc187859…26f2`, previous contract revision; tx `0xe348959ed4bbcb59e463783a6868b6c2c47383d724fe8b3fce5a38784d5ffac0`) | `zkq-prove verify --proof …` → OK under IMAGE_ID `0x77948aba…d9ac` |

## Regenerate the `.bin` fixtures (deterministic — identical bytes)

```bash
scripts/build.sh          # builds crypto/build/gen_fixture and regenerates quorum_ok/quorum_fail
G="crypto/build/gen_fixture --seeds crypto/seeds/computor_seeds.txt --arbitrator-seed crypto/seeds/arbitrator_seed.txt \
   --epoch 999 --message 'Hello ZK, this is Qubic!' --commits 500"
$G --out fixtures/quorum_ok.bin
$G --bad-commits 200  --out fixtures/quorum_fail.bin
$G --wrong-digest 200 --out fixtures/quorum_wrongdigest.bin
$G --replay-query     --out fixtures/quorum_replay.bin
crypto/build/check_fixture fixtures/quorum_ok.bin $(awk '{print $2}' crypto/seeds/arbitrator_pubkey.txt)   # "fixture OK"
```

Format `ZKQFIX02` (`host/src/fixture.rs`, `SPEC.md` "Wire formats"): magic | packet 21698 B |
queryId u64 | qLen u32 + queryTx | rLen u32 + reply | n u32 + n×(len u32 + commitTx) | vLen u32 + revealTx.
Commit txs sign `K12(tx[..len−64])` and carry `queryId | K12(reply) | K12(reply ‖ computorIndex)` —
exactly what Qubic's oracle engine emits/checks.

## Regenerate the Groth16 receipt (needs GPUs)

```bash
# bento farm per docs/BENTO.md, then:
RISC0_DEV_MODE=0 BONSAI_API_URL=http://<bento-host>:8081 BONSAI_API_KEY=anything \
  target/release/zkq-prove --fixture fixtures/quorum_ok.bin --mode groth16 --out fixtures/quorum_ok.groth16.json
target/release/zkq-prove verify --proof fixtures/quorum_ok.groth16.json
```
~215 M cycles; ~5 min on 4 × RTX 4090. The receipt is bound to the guest: a different
arbitrator/toolchain ⇒ different IMAGE_ID ⇒ this receipt no longer verifies. Dev-mode runs
(`RISC0_DEV_MODE=1`) write fake receipts — never a proof.
