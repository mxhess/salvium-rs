#!/usr/bin/env bash
# Run integration tests (requires live testnet daemon)
#
# Usage:
#   ./test/run-integration.sh              # Run all integration tests
#   ./test/run-integration.sh burn-in      # Run burn-in test (full: CN + CARROT)
#   ./test/run-integration.sh burn-in-cn   # Run burn-in CN phase only
#   ./test/run-integration.sh burn-in-carrot # Run burn-in CARROT phase only
#   ./test/run-integration.sh sync         # Sync-only test
#   ./test/run-integration.sh sweep        # Sweep test
#   ./test/run-integration.sh transfer     # Integration transfer test
#   ./test/run-integration.sh stress       # Stress micro-transfer test
set -euo pipefail

cd "$(dirname "$0")/.."

DAEMON_URL="${DAEMON_URL:-http://web.whiskymine.io:29081}"

echo "=========================================="
echo "  salvium-js Integration Tests"
echo "=========================================="
echo "  Daemon: $DAEMON_URL"

# Quick daemon check
if ! bun -e "
import { DaemonRPC } from './src/rpc/daemon.js';
const d = new DaemonRPC({ url: '$DAEMON_URL' });
const i = await d.getInfo();
console.log('  Height: ' + (i.result?.height || 'unknown'));
console.log('  Testnet: ' + (i.result?.testnet || 'unknown'));
" 2>/dev/null; then
  echo "  ERROR: Cannot reach daemon at $DAEMON_URL"
  exit 1
fi
echo ""

PHASE="${1:-all}"

case "$PHASE" in
  burn-in)
    echo "--- Burn-in Test (full) ---"
    bun test/burn-in.test.js
    ;;
  burn-in-cn)
    echo "--- Burn-in Test (CN phase only) ---"
    bun test/burn-in.test.js --phase cn
    ;;
  burn-in-carrot)
    echo "--- Burn-in Test (CARROT phase only) ---"
    bun test/burn-in.test.js --phase carrot
    ;;
  sync)
    echo "--- Sync-Only Test ---"
    bun test/sync-only.js
    ;;
  sweep)
    echo "--- Sweep Test ---"
    bun test/sweep-test.js
    ;;
  transfer)
    echo "--- Integration Transfer Test ---"
    bun test/integration-transfer.test.js
    ;;
  stress)
    echo "--- Stress Micro-Transfer Test ---"
    bun test/stress-micro.test.js
    ;;
  all)
    echo "--- Running all integration tests ---"
    echo ""
    PASSED=0
    FAILED=0

    for test_info in \
      "Sync only:test/sync-only.js" \
      "Integration transfer:test/integration-transfer.test.js" \
      "Burn-in (full):test/burn-in.test.js" \
    ; do
      name="${test_info%%:*}"
      file="${test_info##*:}"
      echo "=== $name ==="
      if bun "$file" 2>&1; then
        PASSED=$((PASSED + 1))
      else
        FAILED=$((FAILED + 1))
        echo "  FAILED: $name"
      fi
      echo ""
    done

    echo "=========================================="
    echo "  Results: $PASSED passed, $FAILED failed"
    echo "=========================================="
    [ $FAILED -gt 0 ] && exit 1
    ;;
  *)
    echo "Unknown phase: $PHASE"
    echo "Usage: $0 [burn-in|burn-in-cn|burn-in-carrot|sync|sweep|transfer|stress|all]"
    exit 1
    ;;
esac
