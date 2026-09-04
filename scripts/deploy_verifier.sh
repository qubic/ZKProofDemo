#!/usr/bin/env bash
# Deploys contracts/QubicQuorumVerifier.sol with (RISC0_ROUTER, built IMAGE_ID) when VERIFIER is empty,
# else verifies the deployed contract's IMAGE_ID == built. IMAGE_ID is immutable: a new guest => new deploy.
set -euo pipefail
source "$(dirname "$0")/lib/config.sh"
cd "$ZKQ_ROOT"
zkq_notice
ALLOW_IMAGE_MISMATCH=1 scripts/check_config.sh >/dev/null || { ALLOW_IMAGE_MISMATCH=1 scripts/check_config.sh; exit 1; }

echo "== build (locked) so IMAGE_ID reflects config/deploy.env"
unset RISC0_SKIP_BUILD; scripts/build.sh >/dev/null
IMAGE_ID=$(target/release/image_id --short)
[[ "$IMAGE_ID" =~ ^0x[0-9a-f]{64}$ ]] || { echo "refusing IMAGE_ID '$IMAGE_ID'"; exit 1; }
zkq_signer || exit 1

if [ -n "${VERIFIER:-}" ]; then
    onchain=$(cast call "$VERIFIER" "IMAGE_ID()(bytes32)" -r "$ETH_RPC")
    if [ "${onchain,,}" = "${IMAGE_ID,,}" ]; then echo "== VERIFIED: $VERIFIER has IMAGE_ID $IMAGE_ID. Nothing to do."; exit 0; fi
    echo "$VERIFIER has IMAGE_ID $onchain, built is $IMAGE_ID. IMAGE_ID is immutable:"
    echo "clear VERIFIER= in $ZKQ_CONFIG and re-run to deploy a new contract."; exit 2
fi

zkq_confirm_mainnet "deploy QubicQuorumVerifier(router=$RISC0_ROUTER, imageId=$IMAGE_ID) on chain $ETH_CHAIN_ID from $ZKQ_SIGNER_ADDR"
out=$(forge create contracts/QubicQuorumVerifier.sol:QubicQuorumVerifier --broadcast \
        --rpc-url "$ETH_RPC" "${ZKQ_SIGNER[@]}" --constructor-args "$RISC0_ROUTER" "$IMAGE_ID" 2>&1) \
    || { echo "$out" | tail -20; echo "deploy failed"; exit 1; }
addr=$(sed -nE 's/^Deployed to: (0x[0-9a-fA-F]{40})$/\1/p' <<<"$out")
[[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "$out" | tail -20; echo "no 'Deployed to:' line"; exit 1; }
onchain=$(cast call "$addr" "IMAGE_ID()(bytes32)" -r "$ETH_RPC")
[ "${onchain,,}" = "${IMAGE_ID,,}" ] || { echo "deployed $addr but IMAGE_ID() = $onchain"; exit 1; }
sed -i "s|^VERIFIER=.*|VERIFIER=$addr|" "$ZKQ_CONFIG"
grep -q "^VERIFIER=$addr\$" "$ZKQ_CONFIG" || { echo "deployed $addr but could not write VERIFIER= in $ZKQ_CONFIG; add it by hand"; exit 1; }
echo "== VERIFIED: deployed $addr with IMAGE_ID $IMAGE_ID; written to $ZKQ_CONFIG"
