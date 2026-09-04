#!/usr/bin/env bash
# Positive demo: build -> fixtures/quorum_ok.bin (500 of 676 commits) -> prove -> verify -> attest on chain.
# RISC0_DEV_MODE=1 (default): fake receipt, no chain submit. RISC0_DEV_MODE=0: real proof via bento
# (BONSAI_API_URL/KEY), then attest(journal, seal) on VERIFIER with the configured signer.
set -euo pipefail
source "$(dirname "$0")/lib/config.sh"
cd "$ZKQ_ROOT"
BIN=target/release
export RISC0_DEV_MODE=${RISC0_DEV_MODE:-1}
PROOF=${PROOF:-fixtures/quorum_ok.proof.json}

[ -x "$BIN/zkq-prove" ] && [ -f fixtures/quorum_ok.bin ] || scripts/build.sh

echo "== prove fixtures/quorum_ok.bin (RISC0_DEV_MODE=$RISC0_DEV_MODE, mode groth16)"
"$BIN/zkq-prove" --fixture fixtures/quorum_ok.bin --out "$PROOF" --mode groth16
echo "== local verify"
if [ "$RISC0_DEV_MODE" = 1 ]; then
    echo "   (dev mode: fake receipt, NOT a proof)"; "$BIN/zkq-prove" verify --proof "$PROOF" --allow-fake
else
    "$BIN/zkq-prove" verify --proof "$PROOF"
fi

field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$PROOF" "$1"; }
# journal (44 B) = epoch u32 LE | queryId u64 LE | K12(reply) 32 B; hex offsets 2 | 10 | 26.
JOURNAL_HEX=$(field journal_hex); SEAL_HEX=$(field seal_hex); KIND=$(field receipt_kind)
[ ${#JOURNAL_HEX} = 90 ] || { echo "ERROR: journal_hex is not 44 bytes: $JOURNAL_HEX"; exit 1; }
le() { python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1]), 'little'))" "$1"; }
EPOCH=$(le "${JOURNAL_HEX:2:8}"); QUERY_ID=$(le "${JOURNAL_HEX:10:16}"); DIGEST=0x${JOURNAL_HEX:26}
echo "journal: $JOURNAL_HEX"
echo "epoch:   $EPOCH"
echo "queryId: $QUERY_ID"
echo "digest:  $DIGEST   (= K12(reply))"
echo "image:   $("$BIN/image_id" --short)"

if [ "$KIND" != groth16 ]; then
    echo "== attest skipped: receipt_kind=$KIND is not groth16 (RISC0_DEV_MODE=0 + bento for a real proof)"; exit 0
fi
[ -n "${VERIFIER:-}" ] || { echo "== attest skipped: VERIFIER empty (scripts/deploy_verifier.sh)"; exit 0; }
zkq_signer || exit 1
zkq_confirm_mainnet "attest(journal, seal) on $VERIFIER (chain $ETH_CHAIN_ID)"
echo "== attest on chain $ETH_CHAIN_ID"
TX=$(cast send "$VERIFIER" "attest(bytes,bytes)" "$JOURNAL_HEX" "$SEAL_HEX" "${ZKQ_SIGNER[@]}" -r "$ETH_RPC" --json \
     | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['transactionHash'], 'status', d['status'], 'gas', int(d['gasUsed'],16))")
echo "tx: $TX"
echo -n "isAttested($DIGEST, $EPOCH) = "; cast call "$VERIFIER" "isAttested(bytes32,uint32)(bool)" "$DIGEST" "$EPOCH" -r "$ETH_RPC"
echo -n "attestedQueryId = ";              cast call "$VERIFIER" "attestedQueryId(bytes32,uint32)(uint64)" "$DIGEST" "$EPOCH" -r "$ETH_RPC"
