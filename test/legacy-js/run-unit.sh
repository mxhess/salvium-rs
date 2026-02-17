#!/usr/bin/env bash
# Run all offline unit tests (no daemon required)
#
# Two test styles:
#   - Custom runner tests: run with `bun <file>`
#   - Bun test runner tests (describe/test): run with `bun test <file>`
#
# Note: Some tests that import from src/index.js (barrel export) fail due to
# a pre-existing hashToPoint re-export issue in bulletproofs_plus.js.
# Tests that import directly from submodules are unaffected.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=========================================="
echo "  salvium-js Unit Tests"
echo "=========================================="
echo ""

PASSED=0
FAILED=0
SKIPPED=0
ERRORS=""

# Run a test file with `bun <file>`
run_test() {
  local name="$1"
  local file="$2"
  printf "  %-40s" "$name"
  if output=$(bun "$file" 2>&1); then
    echo "OK"
    PASSED=$((PASSED + 1))
  else
    echo "FAIL"
    FAILED=$((FAILED + 1))
    ERRORS="$ERRORS\n--- $name ---\n$output\n"
  fi
}

# Run a test file with `bun test <file>` (for describe/test style)
run_bun_test() {
  local name="$1"
  local file="$2"
  printf "  %-40s" "$name"
  if output=$(bun test "$file" 2>&1); then
    echo "OK"
    PASSED=$((PASSED + 1))
  else
    echo "FAIL"
    FAILED=$((FAILED + 1))
    ERRORS="$ERRORS\n--- $name ---\n$output\n"
  fi
}

skip_test() {
  local name="$1"
  local reason="$2"
  printf "  %-40s" "$name"
  echo "SKIP ($reason)"
  SKIPPED=$((SKIPPED + 1))
}

echo "--- Core tests (direct imports) ---"
run_test "Transaction (parsing, signing)"   test/transaction.test.js
run_test "Wallet encryption (PQ hybrid)"    test/wallet-encryption.test.js
run_test "Wallet class"                     test/wallet-class.test.js
run_test "Wallet store"                     test/wallet-store.test.js
run_test "UTXO selection"                   test/utxo-selection.test.js
run_test "CARROT enote types"               test/carrot-enote-type.test.js
run_test "Wallet sync"                      test/wallet-sync.test.js

echo ""
echo "--- Tests using barrel export (src/index.js) ---"
run_test "Core (base58, keccak, address)"   test/run.js
run_test "Keys (derivation)"                test/keys.test.js
run_test "Mnemonic (seed words)"            test/mnemonic.test.js
run_test "Address (encode/decode)"          test/address.test.js
run_test "Subaddress"                       test/subaddress.test.js
run_test "Key image"                        test/keyimage.test.js
run_test "Scanning"                         test/scanning.test.js
run_test "Bulletproofs+"                    test/bulletproofs_plus.test.js
run_test "Blake2b"                          test/blake2b.test.js

echo ""
echo "--- Bun test runner tests ---"
run_bun_test "Validation"                   test/validation.test.js
run_bun_test "Consensus helpers"            test/consensus-helpers.test.js
run_bun_test "Cross-fork TX"               test/cross-fork-tx.test.js
run_bun_test "Wallet reorg"                test/wallet-reorg.test.js
run_bun_test "Stake transaction"           test/stake-transaction.test.js
run_bun_test "Burn transaction"            test/burn-transaction.test.js
run_bun_test "Convert transaction"         test/convert-transaction.test.js
run_bun_test "Audit transaction"           test/audit-transaction.test.js
run_bun_test "Oracle"                      test/oracle.test.js
run_bun_test "Dynamic block size"          test/dynamic-block-size.test.js
run_bun_test "Blockchain"                  test/blockchain.test.js

echo ""
echo "=========================================="
echo "  Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
  echo ""
  echo "Failures:"
  echo -e "$ERRORS"
  exit 1
fi
