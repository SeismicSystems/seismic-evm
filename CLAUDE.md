# Seismic EVM (alloy-seismic-evm)

Fork of [alloy-evm](https://github.com/alloy-rs/alloy-evm) — an EVM abstraction layer on top of [revm](https://github.com/bluealloy/revm). Adds **encrypted transaction support** for the Seismic blockchain: transactions arrive with encrypted inputs, and the block executor decrypts them via a secure enclave before execution, providing on-chain transaction privacy.

## What This Does

Standard EVM transactions have publicly visible calldata. Seismic wraps the alloy-evm block executor to decrypt transaction inputs before execution using keys from a secure enclave (`seismic-enclave`). The architecture is layered: `alloy-evm` (generic) → `alloy-op-evm` (Optimism) → `alloy-seismic-evm` (Seismic). Key additions:

- **`SeismicEvm`** — wrapper around `seismic-revm::SeismicEvm` with optional inspector/tracing support and Seismic-specific transaction types (`SeismicTransaction` with `RngMode`)
- **`SeismicEvmFactory`** — creates EVMs pre-loaded with purpose keys (RNG keypair from enclave) at boot time
- **`SeismicBlockExecutor`** — wraps `EthBlockExecutor`, decrypts tx inputs via `plaintext_copy()` using `tx_io_sk` before delegating to inner executor
- **`SeismicHardfork`** — defines "Mercury" hardfork (active at block 0); all Ethereum forks before Prague are assumed active

## Build

Rust workspace using Cargo. MSRV: 1.88. Edition: 2021.

### macOS

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build
```

### Linux (Ubuntu)

```bash
# Dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build
```

### Verify

```bash
cargo build 2>&1 | tail -1
# Expected: Finished `dev` profile [unoptimized + debuginfo] target(s) in ...
```

## Test

```bash
# Default features (15 unit tests + 1 doc-test) — the standard CI command
cargo test

# All features (19 unit tests + 1 doc-test, adds overrides/call-util tests)
cargo test --all-features
```

### Warnings-as-errors (CI check)

```bash
RUSTFLAGS="-D warnings" cargo check
```

### Format check (requires nightly for full config)

```bash
# With stable (partial — some rustfmt options are nightly-only)
cargo fmt --all --check

# With nightly (full)
cargo +nightly fmt --all --check
```

## Project Layout

```
crates/
  evm/                    Core EVM abstraction (alloy-evm)
    src/
      lib.rs              Re-exports: Database, Evm, EvmFactory, EthEvm, etc.
      evm.rs              Evm trait + EvmFactory trait definitions
      block/              Block execution: BlockExecutor, BlockExecutorFactory, state changes
        system_calls/     EIP system call implementations (2935, 4788, 7002, 7251)
      eth/                Ethereum-specific: EthEvm, EthBlockExecutor, EIP-6110 deposits
      tx.rs               Transaction conversion traits (IntoTxEnv, FromRecoveredTx, etc.)
      precompiles.rs      Precompile registry and mapping
      tracing.rs          Inspector/tracing support
      overrides.rs        State override utilities (feature-gated: "overrides")
      call.rs             Call utilities (feature-gated: "call-util")
  op-evm/                 Optimism EVM specialization (alloy-op-evm)
    src/block/            OP block executor with Canyon hard fork support
  seismic-evm/            Seismic EVM specialization (alloy-seismic-evm)
    src/
      lib.rs              SeismicEvm, SeismicEvmFactory
      hardfork.rs         SeismicHardfork (Mercury), SeismicChainHardforks
      block/
        mod.rs            SeismicBlockExecutor (decrypts tx inputs before execution)
        receipt_builder.rs  Seismic receipt construction
```

## Key Seismic Files

- **`crates/seismic-evm/src/lib.rs`** — `SeismicEvm` (wraps revm), `SeismicEvmFactory` (stores `&'static GetPurposeKeysResponse`)
- **`crates/seismic-evm/src/block/mod.rs`** — `SeismicBlockExecutor` — the core Seismic logic: calls `plaintext_copy(&purpose_keys.tx_io_sk, signer)` to decrypt tx input before execution
- **`crates/seismic-evm/src/hardfork.rs`** — `SeismicHardfork::Mercury` at block 0; all Ethereum forks < Prague active

## Dependencies (Seismic-specific)

All pulled via `[patch.crates-io]` pointing to SeismicSystems GitHub forks:

- **`seismic-enclave`** — enclave key management (`GetPurposeKeysResponse`, `tx_io_sk`, `rng_keypair`)
- **`seismic-revm`** — Seismic revm fork (`SeismicContext`, `SeismicInstructions`, `SeismicPrecompiles`, `SeismicSpecId`)
- **`seismic-alloy-consensus`** — Seismic tx types (`TxSeismic`, `SeismicTxEnvelope`, `InputDecryptionElements`)
- **`seismic-alloy-core`** — patched alloy-primitives/sol-types

## Code Style

- **rustfmt.toml**: `max_width = 100`, `imports_granularity = Crate`, `reorder_imports = true` (some options require nightly)
- **clippy.toml**: MSRV 1.88
- **Workspace lints**: `unused-must-use = deny`, `rust-2018-idioms = deny`, `missing-docs = warn`, clippy all warnings
- Conventional commits: `feat:`, `fix:`, `chore:`, etc.

## CI

GitHub Actions (`.github/workflows/`):

- **seismic.yml** (push/PR to `seismic`): `cargo fmt --check`, `cargo build`, `RUSTFLAGS="-D warnings" cargo check`, `cargo test`
- **ci.yml** (upstream): matrix testing, WASM/no_std/riscv targets, clippy, docs, feature powerset

## Branches

- `seismic` — main branch (PR target)
- `develop` — upstream alloy-evm tracking

## Troubleshooting

| Problem                                                                                         | Fix                                                                                                                                                |
| ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cargo test --no-default-features` fails in `revm-interpreter` with `could not find mem in std` | Known upstream issue in `seismic-revm` fork — `no_std` build uses `std::mem` without import. Use default features or `--all-features` for testing. |
| `cargo fmt` warns about unstable features (`wrap_comments`, `imports_granularity`, etc.)        | Several `rustfmt.toml` options require nightly. Use `cargo +nightly fmt` for full formatting. Stable fmt still works for basic checks.             |
| Compiler warnings about `deprecated method GenericArray::as_slice` in seismic-evm tests         | Harmless deprecation from `k256`/`generic-array` version mismatch. Does not affect correctness.                                                    |
| Unused import warnings in `eip6110.rs` tests                                                    | Known — 4 unused imports in test module. Does not affect build or tests.                                                                           |
| Build slow on first run (fetching git deps)                                                     | Normal — 5 git repos are cloned from GitHub on first build. Subsequent builds use cached checkouts.                                                |
| `RUSTFLAGS="-D warnings" cargo check` fails                                                     | Warnings exist in test code but `cargo check` doesn't compile tests. If it fails, check for new warnings in library code.                          |
