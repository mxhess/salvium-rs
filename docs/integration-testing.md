# Integration Testing

All integration tests are pure Rust (`#[ignore]`-gated). Run them with `--ignored`.


## Prerequisites

1. Testnet daemon running (default: `http://node12.whiskymine.io:29081`)
2. Wallet files at `~/testnet-wallet/`:
   - `wallet-a.json` + `wallet-a.pin` (sender)
   - `wallet-b.json` + `wallet-b.pin` (receiver)
3. Miner binary built:
   ```
   cargo build -p salvium-miner --release
   ```


## Full Orchestrator (recommended)

Mines from genesis through all hard forks (HF1-HF10), testing transfers,
stakes, burns, and sweeps at each era boundary.

```bash
cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture
```

With a custom daemon:

```bash
TESTNET_DAEMON_URL=http://localhost:29081 \
  cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture
```

Resume from a specific fork (e.g. after a partial run):

```bash
RESUME_FROM_HF=6 \
  cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture
```


## Individual Test Suites

Run these against an already-synced testnet with funded wallets.
Order matters -- run top-to-bottom for best results.

```bash
# RPC connectivity
cargo test -p salvium-rpc --test testnet -- --ignored --nocapture

# Wallet sync
cargo test -p salvium-wallet --test testnet_sync -- --ignored --nocapture

# Transfers
cargo test -p salvium-wallet --test testnet_transfer -- --ignored --nocapture

# Stakes
cargo test -p salvium-wallet --test testnet_stake -- --ignored --nocapture

# Burns
cargo test -p salvium-wallet --test testnet_burn -- --ignored --nocapture

# Converts (HF255 gated -- expect rejection on current testnet)
cargo test -p salvium-wallet --test testnet_convert -- --ignored --nocapture

# Subaddresses
cargo test -p salvium-wallet --test testnet_subaddress -- --ignored --nocapture

# Decoy selection / ring building
cargo test -p salvium-tx --test testnet -- --ignored --nocapture

# RCT verification against testnet TXs
cargo test -p salvium-tx --test rct_verify_testnet -- --ignored --nocapture

# Consensus simulation
cargo test -p salvium-consensus --test testnet_sim -- --ignored --nocapture

# FFI integration (wallet open/sync/transfer via C ABI)
cargo test -p salvium-ffi --test testnet_ffi -- --ignored --nocapture

# FFI wallet sync
cargo test -p salvium-ffi --test wallet_sync -- --ignored --nocapture

# Run ALL ignored tests at once
cargo test --workspace -- --ignored --nocapture
```


## Testnet Hard Fork Schedule

| HF | Height | Key Changes |
|----|--------|-------------|
| 1 | 1 | Genesis (SAL, BulletproofPlus) |
| 2 | 250 | ENABLE_N_OUTS, 2021-scaling fees |
| 3 | 500 | Full proofs |
| 4 | 600 | Enforce full proofs |
| 5 | 800 | Shutdown user TXs |
| 6 | 815 | AUDIT1, SAL1, SalviumZero |
| 7 | 900 | AUDIT1 pause |
| 8 | 950 | AUDIT2 |
| 9 | 1000 | AUDIT2 pause |
| 10 | 1100 | CARROT (SalviumOne, carrot addresses) |
| 11 | 1200 | ENABLE_TOKENS (CREATE_TOKEN, ROLLUP, TX v5) |


## CLI Manual Testing

```bash
cargo run -p salvium-cli -- --network testnet --daemon http://node12.whiskymine.io:29081 sync
cargo run -p salvium-cli -- --network testnet balance
cargo run -p salvium-cli -- --network testnet transfer --address SLVx... --amount 1.0
cargo run -p salvium-cli -- --network testnet stake --amount 100.0
cargo run -p salvium-cli -- --network testnet create-token --ticker TEST --supply 100000000 --decimals 8
```
