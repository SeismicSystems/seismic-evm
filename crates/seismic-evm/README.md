# Seismic EVM adapter

`alloy-seismic-evm` adapts Seismic transactions and block execution to the Mercury EVM. It selects purpose keys from the parent-state key-rotation registry and decrypts transaction inputs before delegating to the Ethereum block executor.

## Block timestamps

Seismic factories accept `SeismicEvmEnv`, an alias for
`EvmEnv<SeismicSpecId, SeismicBlockEnv>`. The standard `BlockEnv` inside it uses
Unix seconds; `timestamp_millis_part` carries the sub-second component.

```rust
use alloy_primitives::U256;
use alloy_seismic_evm::SeismicEvmEnv;

let mut env = SeismicEvmEnv::default();
env.block_env.timestamp = U256::from(1_800_000_000u64);
env.block_env.timestamp_millis_part = 123;
assert_eq!(env.block_env.timestamp_millis(), U256::from(1_800_000_000_123u64));
```

Normal execution, inspected execution, system calls and `Evm::finish()` preserve
the component. `Evm::block()` exposes the standard seconds-based inner environment
for common block-execution logic. `TIMESTAMP` remains seconds, while Seismic's
`TIMESTAMPMS` (`0x4B`) returns `seconds * 1000 + timestamp_millis_part`.

Fork checks for Cancun/Prague and standard block timestamps always use seconds;
the `timestamp-in-seconds` features have been removed. Seismic's beacon-roots
contract still indexes entries in full milliseconds.

Execution clients must populate the component from both existing headers and
next-block attributes and validate that it is in `0..1000`. Converting a standard
`BlockEnv` with `.into()` assigns a zero component, not recovered precision.
Mutate Seismic environment fields directly as above; `EvmEnv`'s standard
`BlockEnv` convenience setters remain available for Ethereum/OP environments.

## Gas-payment metadata

The shared `alloy-evm::tx::gas_payment_to_env` conversion preserves the authenticated consensus selector in the execution environment:

- `Auto`: native first, otherwise one individually affordable registered token.
- `Native`: native currency only.
- `Token(address)`: exactly that registered token, with no fallback.

Standard transaction envelopes map to `Auto`. Seismic envelope, recovered, and encoded conversion routes preserve the selector, signed-read intent, and envelope hash. Conversion from an unsigned `TxSeismic` preserves execution fields and metadata but has no signed envelope hash; its execution hash remains the default zero value. The adapter does not select a token itself: `seismic-revm` resolves and settles payment against the current journal.

On decryption failure, the execution wrapper changes only the environment value to zero and marks decryption as failed. Signed transaction fields, encrypted input, selector, and envelope hash remain unchanged. The handler skips bytecode execution but still consumes the nonce and settles fees using intrinsic gas and the applicable calldata gas floor.

## Request-local signed-read simulations

Ordinary block factories validate transaction expiry/recent-block freshness and decrypt inputs. A wire `signed_read` flag alone does not enable a bypass.

`SeismicBlockExecutorFactory::with_plaintext_signed_reads()` is an explicit opt-in for request-local RPC simulations whose ingress has already authenticated the signature, validated signed-read intent and tip freshness, and decrypted the input. These plaintext signed reads must not be decrypted again or have their expiry rechecked at a future simulated height. This option is not authentication or a fee exemption: ordinary EVM validation and accounting still apply.

Never enable this option on factories used for payload building or received blocks. Ordinary encrypted transactions continue through live freshness/decryption handling even on an opted-in simulation factory. The adapter relies on its caller to enforce the RPC ingress contract; it does not independently authenticate plaintext requests.

Both execution entry points share the same handling. The transaction-hash accumulator advances only for committed transactions; rejected and non-committed transactions do not advance it.

## Targeted verification

```sh
CARGO_BUILD_JOBS=1 cargo test --locked -p alloy-evm -p alloy-seismic-evm \
  --lib --tests -- --test-threads=1
cargo +nightly fmt --all --check
```

The workspace manifest pins published Seismic Alloy and revm commits. Verification for publication must use those pins without local dependency overrides. Optional Optimism features and broad workspace checks are separate scopes.
