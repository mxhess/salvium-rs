# Salvium-JS Testnet Testing Plan

**Status:** Pending - to be executed near project completion

---

## Security: No Secrets in Git

**Pre-commit hook installed:** `.githooks/pre-commit` scans for potential secrets before commit.

**Setup:** Run `git config core.hooksPath .githooks` to enable.

**Protected patterns:**
- 25-word mnemonic phrases
- 64-character hex strings (potential keys)
- Files matching `*.env`, `*.key`, `wallet*.json`, etc.

**Git history audit (2026-01-25):** No real wallet credentials found in history. Only test patterns (`bacon bacon...`, `abbey abbey...`) which are recognizable fake mnemonics.

---

## Prerequisites

### Testnet Setup
- [ ] Testnet daemon URL (or run local testnet node)
- [ ] Testnet wallet with funds (need testnet SAL faucet or mining)
- [ ] Second wallet for receiving transactions

### Environment Variables

**CRITICAL: All wallet secrets MUST come from environment variables. Never hardcode mnemonics, master keys, view keys, or spend keys in test files.**

```bash
# Primary wallet (choose one method)
export WALLET_SEED="testnet wallet 25 word mnemonic"
# OR
export MASTER_KEY="64-character-hex-master-key"
# OR (for view-only testing)
export VIEW_SECRET_KEY="64-char-hex"
export SPEND_PUBLIC_KEY="64-char-hex"

# Secondary wallet for receiving
export WALLET_SEED_2="second wallet mnemonic for receiving"

# Daemon
export DAEMON_URL="http://localhost:28081"  # Testnet port
```

### Supported Key Formats

| Variable | Format | Description |
|----------|--------|-------------|
| `WALLET_SEED` | 25 words | Full wallet from mnemonic |
| `MASTER_KEY` | 64 hex chars | Raw 32-byte seed |
| `VIEW_SECRET_KEY` | 64 hex chars | View-only: view secret |
| `SPEND_PUBLIC_KEY` | 64 hex chars | View-only: spend pubkey |
| `SPEND_SECRET_KEY` | 64 hex chars | Optional: spend secret |

---

## Test Categories

### 1. Wallet Sync & Balance Detection

**Test:** Full sync from genesis
```bash
WALLET_SEED="..." bun test/integration-sync.test.js
```

**Verify:**
- [ ] CN outputs detected correctly
- [ ] CARROT outputs detected correctly
- [ ] Subaddress outputs detected (both CN and CARROT)
- [ ] Integrated address outputs detected
- [ ] Key images computed correctly
- [ ] Spent outputs marked as spent
- [ ] Balance matches expected value
- [ ] Stake/yield outputs identified

**Test:** Partial sync (resume from height)
```bash
START_HEIGHT=10000 WALLET_SEED="..." bun test/integration-sync.test.js
```

---

### 2. TRANSFER Transaction

**Test:** Send SAL to standard address
```bash
WALLET_SEED="..." \
RECIPIENT="SLVx..." \
AMOUNT=1.0 \
DRY_RUN=false \
bun test/transfer-integration.test.js
```

**Verify:**
- [ ] Transaction builds without error
- [ ] CLSAG signatures valid
- [ ] Bulletproofs+ range proofs valid
- [ ] Transaction accepted by daemon
- [ ] Transaction appears in mempool
- [ ] Transaction confirmed in block
- [ ] Recipient wallet detects the output
- [ ] Change output returns to sender

**Test:** Send to subaddress
- [ ] CN subaddress recipient
- [ ] CARROT subaddress recipient

**Test:** Send to integrated address
- [ ] Payment ID embedded correctly
- [ ] Recipient detects with payment ID

---

### 3. STAKE Transaction

**Test:** Create stake
```bash
WALLET_SEED="..." \
STAKE_AMOUNT=100.0 \
DRY_RUN=false \
bun test/stake-integration.test.js
```

**Verify:**
- [ ] txType = 6 (STAKE)
- [ ] unlock_time = current_height + STAKE_LOCK_PERIOD
- [ ] source_asset_type = "SAL"
- [ ] destination_asset_type = "SAL"
- [ ] Transaction accepted by daemon
- [ ] Stake output locked until unlock_time
- [ ] After unlock, RETURN transaction received
- [ ] Yield amount correct per consensus rules

**Test:** Verify lock period
- [ ] Mainnet: 21600 blocks (~30 days)
- [ ] Testnet: 20 blocks (for quick testing)

---

### 4. BURN Transaction

**Test:** Burn SAL
```bash
WALLET_SEED="..." \
BURN_AMOUNT=0.1 \
DRY_RUN=false \
bun test/burn-integration.test.js
```

**Verify:**
- [ ] txType = 5 (BURN)
- [ ] destination_asset_type = "BURN"
- [ ] amount_burnt matches requested amount
- [ ] unlock_time = 0 (no lock)
- [ ] Transaction accepted by daemon
- [ ] Burned coins permanently removed from supply
- [ ] Change output returns correctly

**Test:** Burn SAL1 (if available)
```bash
ASSET_TYPE=SAL1 WALLET_SEED="..." BURN_AMOUNT=0.1 bun test/burn-integration.test.js
```

---

### 5. CONVERT Transaction (When Implemented)

**Test:** Convert SAL to SAL1
```bash
WALLET_SEED="..." \
FROM_ASSET=SAL \
TO_ASSET=SAL1 \
AMOUNT=10.0 \
DRY_RUN=false \
bun test/convert-integration.test.js
```

**Verify:**
- [ ] txType = 4 (CONVERT)
- [ ] source_asset_type correct
- [ ] destination_asset_type correct
- [ ] Oracle price used correctly
- [ ] Slippage limit enforced
- [ ] Transaction accepted by daemon
- [ ] Converted amount received

---

### 6. AUDIT Transaction (When Implemented)

**Test:** Create audit disclosure
```bash
WALLET_SEED="..." \
AUDIT_TYPE=full \
DRY_RUN=false \
bun test/audit-integration.test.js
```

**Verify:**
- [ ] txType = 8 (AUDIT)
- [ ] Disclosure data correct
- [ ] Transaction accepted by daemon

---

### 7. Address Generation

**Test:** All address types generate correctly
```bash
bun test/address-integration.test.js
```

**Verify:**
- [ ] Legacy (CN) main address - starts with SLVx
- [ ] Legacy subaddress - starts with SLVs
- [ ] Legacy integrated address - starts with SLVi
- [ ] CARROT main address - starts with salv
- [ ] CARROT subaddress - starts with salvs
- [ ] CARROT integrated address - starts with salvi
- [ ] All addresses decode back to correct keys

---

### 8. Signature Verification

**Test:** Verify our signatures against daemon
```bash
bun test/signature-verification.test.js
```

**Verify:**
- [ ] CLSAG signatures we create pass daemon verification
- [ ] Bulletproofs+ we create pass daemon verification
- [ ] Message signatures verify correctly

---

### 9. RPC Methods

**Test:** All daemon RPC methods work
```bash
bun test/rpc.integration.js $DAEMON_URL
```

**Verify:**
- [ ] getInfo
- [ ] getBlockCount
- [ ] getBlock / getBlockByHeight
- [ ] getTransactions
- [ ] sendRawTransaction
- [ ] getOuts (for ring member selection)
- [ ] getOutputDistribution
- [ ] Salvium-specific: getSupplyInfo, getYieldInfo

---

### 10. Edge Cases

**Multi-input transactions:**
- [ ] Transaction with 2+ inputs
- [ ] Mixed CN and CARROT inputs (if applicable)

**Dust handling:**
- [ ] Very small outputs
- [ ] sweepDust function (when implemented)

**Error handling:**
- [ ] Insufficient funds error
- [ ] Invalid address error
- [ ] Network errors (daemon unreachable)
- [ ] Invalid transaction rejection

---

## Test Execution Order

1. **Wallet Sync** - Verify we can scan blockchain correctly
2. **Address Generation** - Verify addresses work
3. **TRANSFER** - Basic send/receive
4. **STAKE** - Staking functionality
5. **BURN** - Burning functionality
6. **CONVERT** - Asset conversion (when ready)
7. **AUDIT** - Compliance features (when ready)
8. **Edge Cases** - Stress testing

---

## Integration Test Scripts Needed

| Script | Status | Description |
|--------|--------|-------------|
| `integration-sync.test.js` | ✅ Exists | Wallet sync |
| `transfer-integration.test.js` | ❌ TODO | Send transactions |
| `stake-integration.test.js` | ❌ TODO | Stake creation |
| `burn-integration.test.js` | ✅ Exists | Burn transactions |
| `convert-integration.test.js` | ❌ TODO | Asset conversion |
| `audit-integration.test.js` | ❌ TODO | Audit transactions |
| `address-integration.test.js` | ❌ TODO | Address roundtrip |
| `signature-verification.test.js` | ❌ TODO | Sig verification |

---

## Success Criteria

All tests pass with:
- [ ] Zero transaction rejections
- [ ] Zero balance discrepancies
- [ ] Zero parsing errors
- [ ] All transaction types confirmed on-chain
- [ ] Recipient wallets detect all sent outputs

---

## Notes

- Always use testnet first - never test with real mainnet funds
- Keep test amounts small (0.01-1 SAL)
- Document any daemon version requirements
- Record block heights of test transactions for debugging
