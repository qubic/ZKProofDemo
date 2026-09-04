# Source me. Loads config/deploy.env (env vars already set win), validates, prints notices.
#   ZKQ_ROOT, zkq_notice, zkq_confirm_mainnet
ZKQ_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZKQ_CONFIG=$ZKQ_ROOT/config/deploy.env   # fixed path: the guest build.rs reads exactly this file
[ -r "$ZKQ_CONFIG" ] || { echo "config missing: $ZKQ_CONFIG"; exit 1; }

# The FILE is the truth. An exported env var that differs from the file is an error (stale shell),
# except for the box-local allowlist below. Stale-shell fix: `unset <VAR>` or open a new shell.
ZKQ_ENV_ALLOW=" BENTO_AGENT BENTO_REST_API BENTO_LOG_DIR SEGMENT_PO2 "
while IFS='=' read -r k v; do
    k=${k//$'\r'/}; k=${k#"${k%%[![:space:]]*}"}
    case "$k" in ''|\#*) continue;; esac
    v=${v//$'\r'/}; v=$(sed -E 's/[[:space:]]+#.*$//' <<<"$v"); v=${v%"${v##*[![:space:]]}"}
    [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "config: bad key '$k'"; exit 1; }
    if [ -n "${!k+x}" ] && [ "${!k}" != "$v" ] && [[ "$ZKQ_ENV_ALLOW" != *" $k "* ]]; then
        case "$k" in *PASSWORD*|*KEY*|*RPC*) echo "config: $k env != file (values hidden); edit $ZKQ_CONFIG and unset $k";;
                     *) echo "config: $k env ('${!k}') != file ('$v'); edit $ZKQ_CONFIG and unset $k";; esac
        exit 1
    fi
    [ -z "${!k+x}" ] && export "$k=$v"
done < "$ZKQ_CONFIG"

for k in ZKQ_PROFILE ZKQ_ARBITRATOR_IDENTITY ETH_CHAIN_ID ETH_RPC RISC0_ROUTER WALLET_FILE \
         BENTO_INFRA_HOST BONSAI_API_URL BONSAI_API_KEY SEGMENT_PO2; do
    [ -n "${!k:-}" ] || { echo "config: $k is empty ($ZKQ_CONFIG)"; exit 1; }
done
case "$ZKQ_PROFILE" in devnet|mainnet) ;; *) echo "config: ZKQ_PROFILE must be devnet|mainnet"; exit 1;; esac
[[ "$ZKQ_ARBITRATOR_IDENTITY" =~ ^[A-Z]{60}$ ]] || { echo "config: ZKQ_ARBITRATOR_IDENTITY must be 60 upper-case letters"; exit 1; }
[[ "$RISC0_ROUTER" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "config: RISC0_ROUTER malformed"; exit 1; }
[ -z "${VERIFIER:-}" ] || [[ "$VERIFIER" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "config: VERIFIER malformed"; exit 1; }
[[ "$ETH_CHAIN_ID" =~ ^[0-9]+$ ]] || { echo "config: ETH_CHAIN_ID must be numeric"; exit 1; }
[[ "$BENTO_INFRA_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "config: BENTO_INFRA_HOST malformed"; exit 1; }
[[ "$SEGMENT_PO2" =~ ^[0-9]+$ ]] || { echo "config: SEGMENT_PO2 must be numeric"; exit 1; }
case "$BENTO_INFRA_HOST" in 127.0.0.1|localhost) ;; *)
    if [ "${BENTO_PG_PASSWORD:-password}" = password ] || [ "${BENTO_MINIO_PASSWORD:-password}" = password ]; then
        echo "config: BENTO_INFRA_HOST=$BENTO_INFRA_HOST is reachable over the network but bento creds are the dev defaults; change BENTO_PG_PASSWORD/BENTO_MINIO_PASSWORD"; exit 1
    fi;;
esac
# host part only, for log lines (RPC URLs may embed provider keys)
zkq_redact_url() { sed -E 's#^([a-z]+://[^/@]*@)?([a-z]+://)?([^/?]*).*#\2\3#' <<<"$1"; }

# Signer for forge/cast: sets ZKQ_SIGNER (arg array) + ZKQ_SIGNER_ADDR. Returns 1 with a message.
#   ETH_ACCOUNT set  -> foundry keystore (`cast wallet import`), password prompted or ETH_PASSWORD_FILE
#   else             -> WALLET_FILE (mode 0600/0400) containing PRIVATE_KEY=0x...; never exported
zkq_signer() {
    ZKQ_SIGNER=(); ZKQ_SIGNER_ADDR=
    if [ -n "${ETH_ACCOUNT:-}" ]; then
        ZKQ_SIGNER=(--account "$ETH_ACCOUNT")
        [ -n "${ETH_PASSWORD_FILE:-}" ] && ZKQ_SIGNER+=(--password-file "$ETH_PASSWORD_FILE")
    else
        [ -r "$WALLET_FILE" ] || { echo "signer: WALLET_FILE not readable: $WALLET_FILE"; return 1; }
        local mode; mode=$(stat -L -c %a "$WALLET_FILE")
        [ "$mode" = 600 ] || [ "$mode" = 400 ] || { echo "signer: $WALLET_FILE must be mode 0600 (is $mode)"; return 1; }
        local pk; pk=$(sed -nE 's/^(export )?PRIVATE_KEY=//p' "$WALLET_FILE" | tr -d '"'"'"' ' | head -1)
        [[ "$pk" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "signer: no PRIVATE_KEY=0x<64 hex> line in $WALLET_FILE"; return 1; }
        ZKQ_SIGNER=(--private-key "$pk")
    fi
    ZKQ_SIGNER_ADDR=$(cast wallet address "${ZKQ_SIGNER[@]}" 2>/dev/null) || { echo "signer: cast wallet address failed"; return 1; }
    [[ "$ZKQ_SIGNER_ADDR" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "signer: bad address"; return 1; }
}

zkq_notice() {
    echo "== profile: $ZKQ_PROFILE | chain $ETH_CHAIN_ID | router $RISC0_ROUTER | verifier ${VERIFIER:-<none, will deploy>}"
    echo "== arbitrator: $ZKQ_ARBITRATOR_IDENTITY (baked into IMAGE_ID)"
    if [ "$ZKQ_PROFILE" = mainnet ]; then
        cat <<'N'
!! MAINNET NOTICES
!!  1. IMAGE_ID = f(guest code, risc0 version, arbitrator identity). Any change => new IMAGE_ID => redeploy the verifier.
!!  2. The on-chain imageId is the ONLY thing that binds proofs to this guest. Verify it after every deploy.
!!  3. Never `cargo update`; build with scripts/build.sh (--locked). bento agents must be the same risc0.
!!  5. Computors packet must be the live arbitrator-signed BroadcastComputors of the epoch you attest.
N
    fi
}

# zkq_confirm_mainnet "<what>": requires the operator to type the exact token on mainnet.
zkq_confirm_mainnet() {
    [ "$ZKQ_PROFILE" = mainnet ] || return 0
    echo "!! about to: $1"
    read -r -p "!! type MAINNET to continue: " ans
    [ "$ans" = MAINNET ] || { echo "aborted"; exit 1; }
}
