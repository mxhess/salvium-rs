#!/usr/bin/env bash
# Run all tests: unit tests first, then integration tests
#
# Usage:
#   ./test/run-all.sh          # Unit + integration tests
#   ./test/run-all.sh --unit   # Unit tests only
#   ./test/run-all.sh --integration [phase]  # Integration tests only
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:---both}"

case "$MODE" in
  --unit)
    bash test/run-unit.sh
    ;;
  --integration)
    shift
    bash test/run-integration.sh "${1:-all}"
    ;;
  --both|*)
    echo "============================================================"
    echo "  salvium-js Full Test Suite"
    echo "============================================================"
    echo ""

    echo ">>> Unit Tests"
    echo ""
    if bash test/run-unit.sh; then
      echo ""
      echo ">>> Unit tests PASSED, running integration tests..."
      echo ""
      bash test/run-integration.sh "${2:-all}"
    else
      echo ""
      echo ">>> Unit tests FAILED, skipping integration tests"
      exit 1
    fi
    ;;
esac
