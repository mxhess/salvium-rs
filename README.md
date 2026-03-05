# salvium-rs

Rust implementation of Salvium cryptocurrency tooling — wallet management, transaction construction, blockchain consensus, cryptographic operations, mining, multisig support, and C FFI for mobile/desktop apps.

## Workspace Crates

| Crate | Description |
|-------|-------------|
| **salvium-crypto** | Core cryptographic primitives: Ed25519/Curve25519, CLSAG/TCLSAG signatures, Bulletproofs+ range proofs, key images, CryptoNote + CARROT output scanning, SQLCipher wallet storage, WASM compilation target |
| **salvium-types** | Shared types: network IDs, address prefixes, consensus constants, hardfork table (HF1–HF11), fee calculation, transaction types, mnemonic seeds (12 languages) |
| **salvium-consensus** | Blockchain consensus: chain state, difficulty, block weight limits, alternative chain management, miner TX creation, block/transaction validation |
| **salvium-wallet** | Wallet functionality: key derivation, address generation (18 types), sync engine, mempool scanning, encrypted storage (AES-256-GCM + Argon2id), UTXO selection, stake lifecycle tracking, token creation, subaddress generation |
| **salvium-tx** | Transaction construction: builder (v2–v5), signing, decoy selection, fee estimation, offline signing (cold wallet support), serialization |
| **salvium-rpc** | Async RPC clients for Salvium daemon (block/tx/output queries, submission) and wallet service |
| **salvium-ffi** | C FFI library for mobile/desktop apps: wallet lifecycle, sync, transfers, staking, sweeps, token creation, mempool scanning, PIN-encrypted blob export/import |
| **salvium-miner** | RandomX proof-of-work mining: large pages, pipelined hashing, Blake2 generator, difficulty checking |
| **salvium-multisig** | M-of-N multisig: key exchange protocol (KEX), partial signatures, transaction sets, CARROT-aware multisig accounts and addresses |
| **salvium-cli** | Command-line wallet: create/restore, sync, transfer, stake, burn, create-token, balance, history, status |

## Building

```bash
cargo build --workspace
cargo build --workspace --release
```

## Testing

```bash
# Run all 1,010 unit + integration tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p salvium-crypto
cargo test -p salvium-wallet
cargo test -p salvium-consensus

# Run testnet integration tests (requires live daemon)
# Default daemon: http://node12.whiskymine.io:29081
cargo test --workspace -- --ignored --nocapture

# Full orchestration test (HF1–HF10 validation, ~2.5 hours)
cargo test -p salvium-tx --test full_testnet -- --ignored --nocapture
```

### Testnet Environment

Testnet integration tests use:

| Variable | Default | Description |
|----------|---------|-------------|
| `TESTNET_DAEMON_URL` | `http://node12.whiskymine.io:29081` | Testnet daemon RPC endpoint |

Wallet files expected at `~/testnet-wallet/`:
- `wallet-a.json` + `wallet-a.pin` (sender)
- `wallet-b.json` + `wallet-b.pin` (receiver)

See [docs/integration-testing.md](docs/integration-testing.md) for full orchestration test documentation.

## CLI Usage

```bash
# Build the CLI
cargo build -p salvium-cli --release

# Testnet operations
salvium-cli --network testnet sync
salvium-cli --network testnet balance
salvium-cli --network testnet transfer --address SaLvT... --amount 1.0
salvium-cli --network testnet stake --amount 100.0
salvium-cli --network testnet create-token --ticker TEST --supply 1000000 --decimals 8
salvium-cli --network testnet history
salvium-cli --network testnet stakes
salvium-cli --network testnet status

# Custom daemon
salvium-cli --network testnet --daemon http://127.0.0.1:29081 sync
```

### Default Daemon Ports

| Network | RPC Port |
|---------|----------|
| Mainnet | 19081 |
| Testnet | 29081 |
| Stagenet | 39081 |

## FFI (Mobile/Desktop)

The `salvium-ffi` crate exposes a C API for integration with Flutter, React Native, Swift, Kotlin, etc.

Key exports:
- `salvium_wallet_create`, `salvium_wallet_open`, `salvium_wallet_close`
- `salvium_wallet_sync`, `salvium_wallet_stop_sync`, `salvium_wallet_scan_mempool`
- `salvium_wallet_transfer`, `salvium_wallet_stake`, `salvium_wallet_sweep`
- `salvium_wallet_create_token`
- `salvium_wallet_get_balance`, `salvium_wallet_get_transfers`, `salvium_wallet_get_outputs`
- `salvium_wallet_export_blob`, `salvium_wallet_import_blob` (PIN-encrypted key storage)

## Address Types

| Network | Format | Standard | Integrated | Subaddress |
|---------|--------|----------|------------|------------|
| Mainnet | Legacy | SaLv... | SaLvi... | SaLvs... |
| Mainnet | CARROT | SC1... | SC1i... | SC1s... |
| Testnet | Legacy | SaLvT... | SaLvTi... | SaLvTs... |
| Testnet | CARROT | SC1T... | SC1Ti... | SC1Ts... |
| Stagenet | Legacy | SaLvS... | SaLvSi... | SaLvSs... |
| Stagenet | CARROT | SC1S... | SC1Si... | SC1Ss... |

## Key Constants

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| Ring size | 16 | 16 |
| Stake lock period | 21,600 blocks | 20 blocks |
| Coinbase lock | 60 blocks | 60 blocks |
| Block target time | 120 seconds | 120 seconds |
| Full reward zone (v5) | 300,000 bytes | 300,000 bytes |

## WASM Support

The `salvium-crypto` crate compiles to `wasm32-unknown-unknown` for browser/JS integration:

```bash
cd crates/salvium-crypto
RUSTFLAGS="-Ctarget-feature=+simd128" \
  wasm-pack build --target web --out-dir ../../src/crypto/wasm
```

## CI/CD

- **CI** (push/PR to main, manual dispatch): formatting, clippy, workspace compile, WASM target check, per-crate test matrix, doc tests — runs on self-hosted runner
- **Release** (on `v*` tags): pre-release tests, cross-platform builds (Android, iOS, Linux, macOS, Windows, WASM), miner binaries, GitHub Release with checksums

## License

Salvium-RS Source-Available License — Copyright (c) 2024-2026 Whisky
