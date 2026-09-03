#!/usr/bin/env bash
# Verifies src/stock_qubic.c matches qubic/core main (kangaroo_twelve.h + four_q.h).
# Needs network. Known local deltas are filtered; any other difference prints as DRIFT.
set -euo pipefail
CRYPTO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
BASE=https://raw.githubusercontent.com/qubic/core/main/src
for f in kangaroo_twelve.h four_q.h; do
  curl -sf -m 30 -o "$T/$f" "$BASE/$f" || { echo "SKIP: cannot fetch $BASE/$f"; exit 0; }
done

# Upstream side: join files, drop CR, core-internal includes, MSVC ROL64 branch, junction pragma.
cat "$T/kangaroo_twelve.h" "$T/four_q.h" | tr -d '\r' \
  | grep -vE '^#include <lib/platform_common/qintrin.h>$|^#include "platform/|^#include "kangaroo_twelve.h"$' \
  | sed '/^#if defined(_MSC_VER)$/,/^#endif$/{/^#define ROL64(a, offset) ((((unsigned long long)/!d}' \
  | awk 'BEGIN{p=0} /#pragma once/{if(++c==2) next} {print}' \
  | grep -v '^ *//' | grep -v '^$' > "$T/up.norm"

# Our side: drop the SPDX header, comments, blanks, and the appended verify_fourq_signature helper.
sed '/^static bool verify_fourq_signature/,$d' "$CRYPTO/src/stock_qubic.c" \
  | tail -n +7 | grep -v '^ *//' | grep -v '^$' > "$T/ours.norm"
# The helper's closing brace of the previous function stays; upstream keeps it too. Compare.
if diff -u "$T/up.norm" "$T/ours.norm" > "$T/drift"; then
  echo "check_upstream OK: stock_qubic.c matches qubic/core main ($(date -u +%F))"
else
  echo "check_upstream DRIFT vs qubic/core main:"; head -40 "$T/drift"; exit 1
fi
