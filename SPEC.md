# ZKProofDemo — specification

Goal: prove end-to-end, with a RISC Zero Groth16 proof verified on Ethereum, that **at least 451
of the 676 epoch computors (list signed by the arbitrator) committed to one oracle reply**. No
trusted-setup ceremony: RISC Zero's standard Groth16 verifier (`RiscZeroVerifierRouter`) is used;
the program identity is the guest IMAGE_ID checked in-circuit.

## Layout
```
ZKProofDemo/
  SPEC.md                    this file
  README.md                  overview + install (docker) + demo walkthrough
  crypto/seeds/              676 devnet computor seeds + arbitrator seed (z×55)
  crypto/                    C library: FourQ/SchnorrQ + KangarooTwelve + Qubic keygen
  methods/                   RISC Zero guest (Rust + cc-linked C) + build.rs
  host/                      Rust host: fixture parsing, prove (dev/local/bento), verify
  fixtures/                  generated: quorum_ok.bin, quorum_fail.bin, …
  contracts/                 Foundry: QubicQuorumVerifier.sol + deploy/attest scripts   (later commit)
  docker/                    Dockerfiles + compose (dev image, bento GPU prover)
  scripts/                   build, config check, deploy, demos, bento farm            (later commit)
  docs/                      ARCHITECTURE, DEPLOY, BENTO, RUST_TO_C, GROTH16_NO_CEREMONY, E2E_REPORT
```

## Constants
- NUMBER_OF_COMPUTORS = 676, QUORUM = 451, EPOCH (demo) = 999, MESSAGE = "Hello ZK, this is Qubic!" (24 B)
- Query tick 1000000, commit tick 1000004, reveal tick 1000007, user seed `a`×55.
- Arbitrator seed `z`×55 → pubkey (32B, hex) `69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5`
  identity `ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG`. Baked into the guest
  from `config/deploy.env` (`ZKQ_ARBITRATOR_IDENTITY`); mainnet uses core's `ARBITRATOR`.
- Qubic key derivation (from core/qubic-cli, reference `crypto/src/stock_qubic.c`):
  seed = 55 lowercase a–z chars → subseed = K12(seed chars mapped to 0..25 bytes, 55B)
  → privateKey = K12(subseed) → publicKey = FourQ ecc_mul_fixed. Sign = SchnorrQ
  `sign(subseed, publicKey, digest32) -> sig64`; verify(publicKey, digest32, sig64).
- Identity encoding: 4×u64 LE → 14 base-26 chars each + 4-char checksum from K12(pubkey,32)&0x3FFFF.

## Wire formats — oracle transaction series (all little-endian, packed, no padding)

The demo reproduces exactly what Qubic's oracle machine does on-chain: a user sends an oracle
**query** transaction, every computor sends a **commit** transaction carrying `K12(reply)` and a
knowledge proof, and one computor sends the **reveal** transaction with the full reply. The guest
proves that ≥451 distinct computors of the arbitrator-signed list committed to the same reply.

- `Computors` packet (core `network_messages/computors.h`):
  `epoch u16 | publicKeys[676] 32B each | signature 64B` = 21698 bytes; arbitrator signs `K12(packet[0..21634))`.
- `Transaction` (core `network_messages/transactions.h`), header 80 B:
  `sourcePublicKey 32 | destinationPublicKey 32 | amount i64 | tick u32 | inputType u16 | inputSize u16 | input[inputSize] | signature 64`
  total = 80 + inputSize + 64; signature = SchnorrQ(source, K12(tx[0 .. 80+inputSize))).
- Query tx (`OracleUserQueryTransactionPrefix`, inputType **10**): destination = zero, amount = fee,
  input = `oracleInterfaceIndex u32 | timeoutMilliseconds u32 | query bytes`.
  Demo: interface 0, timeout 60000, query = MESSAGE. `queryId = (tick << 31) | txIndexInTick`
  (core `oracle_engine.h`); demo txIndexInTick = 0.
- Reply: 1..1008 bytes (MAX_ORACLE_REPLY_SIZE). Demo: reply = MESSAGE (echo oracle).
  `replyDigest = K12(reply)`; `knowledgeProof(i) = K12(reply ‖ computorIndex i as u16 LE)`.
- Commit tx (`OracleReplyCommitTransactionPrefix`, inputType **6**): source = computor pubkey, destination = zero,
  amount = 0, tick > query tick, input = n × item(72 B) `queryId u64 | replyDigest 32 | replyKnowledgeProof 32`. Demo: n = 1.
- Reveal tx (`OracleReplyRevealTransactionPrefix`, inputType **7**): source = a computor, destination = zero, amount = 0,
  input = `queryId u64 | reply`.
- Fixture file `ZKQFIX02` (host/src/fixture.rs; written by `crypto/tools/gen_fixture.c`):
  `magic "ZKQFIX02" | computorsPacket 21698 | queryId u64 | qLen u32 | queryTx[qLen] | rLen u32 | reply[rLen]
   | n u32 | n × (len u32 | commitTx[len]) | vLen u32 | revealTx[vLen]`
- Guest statement (any violation ⇒ `panic!`, i.e. no proof):
  1. packet signature valid under the config-baked arbitrator pubkey; `epoch != 0`; no repeated pubkey in the list.
  2. query tx: inputType 10, destination zero, signature valid under its source, `tick == queryId >> 31`.
  3. reveal tx: inputType 7, destination zero, amount 0, source ∈ list, signature valid, input == `queryId | reply`.
  4. commit txs, counted only if: inputType 6, destination zero, amount 0, `tick > queryTx.tick`, source ∈ list at index i
     not counted before, signature valid over `K12(tx[..len-64])`, and some 72-B item has `queryId == Q`,
     `replyDigest == K12(reply)`, `replyKnowledgeProof == K12(reply ‖ i)`. Stop at 451; `count < 451` ⇒ panic.
- Guest journal (committed, **44 bytes**): `epoch u32 LE | queryId u64 LE | replyDigest 32B`.
- Negative fixtures (`gen_fixture` flags): `--bad-commits N` (corrupted signatures), `--wrong-digest N`
  (commits to another digest), `--replay-query` (commits carry a different queryId) — all must be rejected.

## crypto/ C API (exported, C11, portable, no x86 intrinsics in the rv32im path)
```
void   qubic_k12(const uint8_t* in, size_t inLen, uint8_t out32[32]);
int    fourq_verify(const uint8_t pk[32], const uint8_t sig[64], const uint8_t digest[32]); // 1 = valid
// host-only helpers (may use the stock_qubic.c reference implementation):
int    qubic_seed_to_subseed(const char seed[55], uint8_t subseed[32]);   // 0 = bad seed
void   qubic_subseed_to_keys(const uint8_t subseed[32], uint8_t priv[32], uint8_t pub[32]);
void   qubic_sign(const uint8_t subseed[32], const uint8_t pub[32], const uint8_t digest[32], uint8_t sig[64]);
void   qubic_identity(const uint8_t pub[32], char out61[61], int lowerCase);
```
Sources: port `riscv_fourq_verify.c` + `riscv_tables.c` (header `include/riscv_qubic_crypto.h`;
rv32im-safe, needs `-fno-strict-aliasing -fsigned-char`) and reference `stock_qubic.c` (header
`include/stock_host.h`; x86/AVX2, host only, used for signing + as test oracle), ported from Qubic core.

## Sepolia
- RiscZeroVerifierRouter `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` (RISC Zero standard, Groth16).
- `QubicQuorumVerifier` (solidity 0.8.24, no OZ): constructor(router, imageId, owner, rotationDelay);
  `attest(bytes32 imageId, bytes journal, bytes seal)`: require journal.length==44,
  decode epoch (bytes 0..4, u32 LE) + queryId (bytes 4..12, u64 LE) + digest (bytes 12..44), revert
  `ZeroEpoch` / `EpochOutOfRange` (>65535) before any verify, return (no-op) if already attested,
  revert `ImageNotActive` unless `isImageActive(imageId)`, `router.verify(seal, imageId, sha256(journal))`,
  store `attestations[digest][epoch] = imageId` and `attestedQueryId[digest][epoch] = queryId`, emit
  `QuorumAttested(bytes32 indexed digest, uint32 indexed epoch, bytes32 indexed imageId, uint64 queryId)`.
  Same digest at another epoch is a separate attestation. Views: `isAttested`, `attestedImageId`,
  `attestedQueryId`, `isImageActive`, `imageActiveFrom`, `rotationDelay`.
  Rotation (owner): `proposeImageId(id)` → active at `now + rotationDelay`; `revokeImageId(id)` immediate,
  old attestations keep their imageId. Ownership: two-step `transferOwnership` / `acceptOwnership`, no renounce.
  Consumers MUST recompute `K12(reply)` from the revealed reply and query `(digest, epoch)`, SHOULD
  check `attestedQueryId` and `attestedImageId` — the contract attests digests, not meanings.
- Current deployment: `0xcc187859d82eae77bf82ac8e98c17dd2885b26f2` (`config/deploy.env` `VERIFIER`).
- Deployer wallet: `WALLET_FILE` from `config/deploy.env` (default `.wallet`, gitignored; never commit).

## Demo (scripts/)
- `demo_quorum_ok.sh`: build → `crypto/build/gen_fixture` → prove (RISC0_DEV_MODE=1 fast path, or
  bento GPU via BONSAI_API_URL) → local verify → attest on Sepolia → show tx hash + `isAttested`.
- `demo_quorum_fail.sh`: fixture with 300 valid commits + 200 corrupted signatures →
  prover MUST fail (guest panic) → prints "quorum not reached: proof impossible" and exits 0.
- Everything runnable inside docker (`docker/Dockerfile.dev`: rust + rzup + foundry + gcc).
