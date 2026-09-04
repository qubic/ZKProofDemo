# Architecture

ZKProofDemo proves, with a RISC Zero Groth16 receipt verified on Ethereum, that ≥ 451 of the 676
computors of a Qubic epoch sent `OracleReplyCommit` transactions for the same oracle reply — the
exact on-chain flow of Qubic's oracle machine: **query tx → 676 commit txs → reveal tx**. The
computor list is authenticated by the arbitrator's signature; that public key comes from
`config/deploy.env` and is baked into the guest, hence into `IMAGE_ID`.

## Data flow

```
 user seed (a×55)        crypto/seeds/computor_seeds.txt (676)        crypto/seeds/arbitrator_seed.txt
      │                             │ keygen (crypto/)                            │ keygen
      ▼                             ▼                                             ▼
 query tx (type 10) ──► queryId ──► commit tx ×676 (type 6)             Computors packet (21698 B)
   input = iface | timeout | query   input = queryId | K12(reply) | K12(reply‖i)   epoch | pubkeys[676] | sig
   queryId = tick<<31 | txIndex      ──► reveal tx (type 7): queryId | reply        ▲ arbitrator signs K12(packet[..21634])
                                                       │                              │
             crypto/build/gen_fixture (C)  ──►  fixtures/quorum_ok.bin (ZKQFIX02)  ◄──┘
                                                       │
                                                       ▼ ExecutorEnv (host/src/fixture.rs, 6 positional frames)
                   ┌──────────────── RISC Zero zkVM guest (methods/guest) ─────────────────┐
                   │ 1. fourq_verify(ARBITRATOR_PK, packet.sig, K12(packet[..21634]))       │
                   │    epoch != 0, no duplicate pubkey                                    │
                   │ 2. query tx: type 10, dest 0, sig valid, tick == queryId >> 31        │
                   │ 3. reveal tx: type 7, source ∈ list, sig valid, input == queryId|reply│
                   │    D = K12(reply)                                                     │
                   │ 4. each commit tx: type 6, dest 0, amount 0, tick > query tick,       │
                   │    source = pubkeys[i] (i distinct), sig over K12(tx[..len-64]),      │
                   │    item {queryId, D, K12(reply‖i)} present; count ≥ 451 else panic!   │
                   │ 5. commit journal: epoch u32 | queryId u64 | D 32 B  (44 bytes)       │
                   └───────────────────────────────────────────────────────────────────────┘
                                                       │
                       STARK (segments → join → succinct)  [RISC0_DEV_MODE=1: fake receipt]
                                                       │  bento GPU farm (BONSAI_API_URL)
                                                       ▼
                                 Groth16 seal (~256 B) via RISC Zero's universal wrap circuit
                                                       │
                                                       ▼ host: proof.json = journal_hex + seal_hex
              Ethereum  QubicQuorumVerifier.attest(journal, seal)
                         └─ return if (digest, epoch) already attested
                         └─ RiscZeroVerifierRouter.verify(seal, IMAGE_ID, sha256(journal))
                         └─ isAttested[digest][epoch] = true; attestedQueryId[digest][epoch] = queryId
                         └─ emit QuorumAttested(digest, epoch, queryId)
```

Guest cost: ≈ 215 M cycles for `fixtures/quorum_ok.bin` (452 SchnorrQ verifies; field
multiplications use the bigint2 precompile — `methods/README.md`). Prove path: `RISC0_DEV_MODE=1`
(no proof) or bento via `BONSAI_API_URL` (`BENTO.md`).

## Wire formats (`SPEC.md` is normative; all little-endian, packed)

| Item | Layout | Size |
|---|---|---|
| `Computors` packet | `epoch u16 \| publicKeys[676]×32 \| signature 64`; arbitrator signs `K12(packet[..21634])` | 21698 |
| `Transaction` | `source 32 \| dest 32 \| amount i64 \| tick u32 \| inputType u16 \| inputSize u16 \| input \| sig 64`; sig = SchnorrQ(source, `K12(tx[..len-64])`) | 144 + inputSize |
| Query tx (type 10) | dest 0, input `interface u32 \| timeoutMs u32 \| query`; `queryId = tick << 31 \| txIndex` | 152 + len(query) |
| Commit tx (type 6) | computor `i`, dest 0, amount 0, input n × `queryId \| K12(reply) \| K12(reply ‖ i u16)` | 144 + 72n |
| Reveal tx (type 7) | a computor, dest 0, amount 0, input `queryId \| reply` (1..1008 B) | 152 + len(reply) |
| Fixture `ZKQFIX02` | `magic \| packet \| queryId \| qLen,queryTx \| rLen,reply \| n, n×(len,commitTx) \| vLen,revealTx` | variable |
| Journal | `epoch u32 \| queryId u64 \| K12(reply)` | 44 |

Host write order and guest read order are positional frames (`len u32 | bytes`) and must stay in
sync (`Fixture::to_env` ↔ guest `read_frame`), as must the 44-byte journal layout with the contract.

## On-chain (`contracts/QubicQuorumVerifier.sol`)

Single file, no dependencies, `IRiscZeroVerifier` inlined. `constructor(router, imageId)`, both
immutable. `attest(journal, seal)`: length 44, `epoch != 0`, no-op if `(digest, epoch)` attested,
`router.verify(seal, IMAGE_ID, sha256(journal))`, then records `isAttested` and `attestedQueryId`.
A new guest (new `IMAGE_ID`) is a new deployment. Consumers know the reply bytes (revealed on
Qubic), recompute `K12(reply)` and query `(digest, epoch)`; the contract attests digests, not meanings.

## Trust model

Proved by a valid `attest`: (1) a `Computors` packet for `epoch` verifies under the baked-in
arbitrator key; (2) ≥ 451 distinct members of that list signed a commit for `{queryId, K12(reply),
K12(reply ‖ i)}` after a signed query, and a member signed the reveal `queryId | reply`; (3) the
program that checked this is exactly `IMAGE_ID` (receipt claim binds `IMAGE_ID` + `sha256(journal)`).

Not proved: reply meaning; tick inclusion or oracle timeout; that the packet is *the* canonical
list of the epoch (the arbitrator could sign several); freshness. See `SECURITY.md`.

Trust roots: arbitrator key (config → `IMAGE_ID`; demo = public seed `z`×55), RISC Zero
router/verifier and its one-time universal ceremony, the C crypto port
(differential-tested against core's reference, `crypto/README.md`).
