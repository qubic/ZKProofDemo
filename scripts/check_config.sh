#!/usr/bin/env bash
# Validates config/deploy.env against the chain, the built guest and the bento farm. Exit 1 on any FAIL.
set -euo pipefail
source "$(dirname "$0")/lib/config.sh"
cd "$ZKQ_ROOT"
rpc() { local i o; for i in 1 2 3; do o=$("$@" 2>/dev/null) && [ -n "$o" ] && { echo "$o"; return 0; }; sleep 2; done; return 1; }
fail=0; ok() { echo "OK   $1"; }; bad() { echo "FAIL $1"; fail=1; }; warn() { echo "WARN $1"; }
zkq_notice

# 1. arbitrator identity: checksum, devnet seed, and what the built guest was baked with
unset RISC0_SKIP_BUILD
RISC0_BUILD_LOCKED=1 cargo build --release --locked --bin zkq_identity --bin image_id >/dev/null 2>&1 || bad "cargo build --locked failed"
if out=$(target/release/zkq_identity "$ZKQ_ARBITRATOR_IDENTITY" 2>&1); then ok "arbitrator identity checksum"; else bad "arbitrator identity: $out"; fi
if [ "$ZKQ_PROFILE" = devnet ]; then
    seed_id=$(awk '{print $3}' crypto/seeds/arbitrator_pubkey.txt)
    [ "$seed_id" = "$ZKQ_ARBITRATOR_IDENTITY" ] && ok "devnet arbitrator = crypto/seeds/arbitrator_seed.txt" \
        || bad "devnet arbitrator != seed-derived $seed_id (gen_fixture would sign with the wrong key)"
fi
if [ "$ZKQ_PROFILE" = mainnet ] && [ "$ZKQ_ARBITRATOR_IDENTITY" != AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ ]; then
    [ "${ALLOW_CUSTOM_ARBITRATOR:-0}" = 1 ] && warn "mainnet with a non-core arbitrator" || bad "mainnet profile but arbitrator is not core's ARBITRATOR (ALLOW_CUSTOM_ARBITRATOR=1 to override)"
fi
built_id=$(target/release/image_id 2>/dev/null | awk '/arbitrator identity/{print $3}')
[ "$built_id" = "$ZKQ_ARBITRATOR_IDENTITY" ] && ok "built guest arbitrator == config" || bad "built guest arbitrator '$built_id' != config (scripts/build.sh)"
built=$(target/release/image_id --short 2>/dev/null || echo "")
[[ "$built" =~ ^0x[0-9a-f]{64}$ ]] && ok "built IMAGE_ID $built" || bad "built IMAGE_ID missing ('$built')"

# 2. Ethereum: chain id, router, signer
if cid=$(rpc cast chain-id -r "$ETH_RPC"); then
    [ "$cid" = "$ETH_CHAIN_ID" ] && ok "ETH_RPC $(zkq_redact_url "$ETH_RPC") chain id $cid" || bad "ETH_RPC chain id $cid != ETH_CHAIN_ID $ETH_CHAIN_ID"
else bad "ETH_RPC unreachable: $(zkq_redact_url "$ETH_RPC")"; fi
case "$ETH_CHAIN_ID" in 1) exp=0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319;; 11155111) exp=0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187;; *) exp=;; esac
if [ -n "$exp" ]; then
    [ "${RISC0_ROUTER,,}" = "${exp,,}" ] && ok "RISC0_ROUTER is the risc0 router for chain $ETH_CHAIN_ID" || bad "RISC0_ROUTER != risc0-ethereum router $exp"
else warn "chain $ETH_CHAIN_ID: router not in the known table (risc0-ethereum deployment.toml)"; fi
[[ "$(rpc cast code "$RISC0_ROUTER" -r "$ETH_RPC")" =~ ^0x[0-9a-f]{2,}$ ]] && ok "router has code" || bad "no code at RISC0_ROUTER"
signer_log=$(mktemp)
if zkq_signer >"$signer_log" 2>&1; then
    ok "signer $ZKQ_SIGNER_ADDR balance $(cast balance --ether "$ZKQ_SIGNER_ADDR" -r "$ETH_RPC" 2>/dev/null || echo '?') ETH"
else bad "signer: $(cat "$signer_log")"; fi; rm -f "$signer_log"

# 3. deployed verifier: immutable IMAGE_ID and ROUTER must match the build and the config
if [ -n "${VERIFIER:-}" ]; then
    if onchain=$(rpc cast call "$VERIFIER" "IMAGE_ID()(bytes32)" -r "$ETH_RPC"); then
        [ "${onchain,,}" = "${built,,}" ] && ok "VERIFIER IMAGE_ID == built" \
            || { [ "${ALLOW_IMAGE_MISMATCH:-0}" = 1 ] && warn "VERIFIER IMAGE_ID $onchain != built (deploy_verifier.sh redeploys)" || bad "VERIFIER IMAGE_ID $onchain != built $built: clear VERIFIER= and run scripts/deploy_verifier.sh"; }
        r=$(cast call "$VERIFIER" "ROUTER()(address)" -r "$ETH_RPC"); [ "${r,,}" = "${RISC0_ROUTER,,}" ] && ok "VERIFIER router matches" || bad "VERIFIER ROUTER $r != RISC0_ROUTER"
    else bad "VERIFIER $VERIFIER: IMAGE_ID() call failed (wrong address/chain, or an older contract version)"; fi
else warn "VERIFIER empty: deploy_verifier.sh will deploy"; fi

# 4. bento: reachable, and agent risc0 == Cargo.lock (else control_id mismatch at prove time)
curl -sf -m 5 "$BONSAI_API_URL/health" >/dev/null && ok "bento rest_api $BONSAI_API_URL" || warn "bento rest_api not reachable ($BONSAI_API_URL): real proving impossible"
if [ -x "$BENTO_AGENT" ]; then
    av=$(strings "$BENTO_AGENT" | grep -oE 'risc0-zkvm-[0-9]+\.[0-9]+\.[0-9]+' | sed 's/risc0-zkvm-//' | sort -u | tr '\n' ' ' | sed 's/ $//')
    cv=$(grep -A1 '^name = "risc0-zkvm"$' Cargo.lock | tail -1 | sed 's/.*"\(.*\)"/\1/')
    [ "$av" = "$cv" ] && ok "bento agent risc0 $av == client $cv" || bad "bento agent risc0 '$av' != client $cv"
else warn "BENTO_AGENT not on this box ($BENTO_AGENT); run scripts/bento/status.sh on the farm"; fi

[ $fail = 0 ] && echo "== config OK" || { echo "== config has FAILures"; exit 1; }
