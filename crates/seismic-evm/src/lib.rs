#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_evm::{Database, Evm, EvmEnv, EvmFactory, IntoTxEnv};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use core::ops::{Deref, DerefMut};
use revm::{
    context::{result::InvalidTransaction, BlockEnv, TxEnv},
    context_interface::{
        result::{EVMError, HaltReason, ResultAndState},
        ContextTr,
    },
    database_interface::EmptyDB,
    handler::PrecompileProvider,
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    Context, ExecuteEvm, InspectEvm, Inspector,
};
use seismic_revm::{
    instructions::instruction_provider::SeismicInstructions, precompiles::SeismicPrecompiles,
    transaction::abstraction::SeismicTransaction, DefaultSeismicContext, SeismicBuilder,
    SeismicContext, SeismicSpecId,
};

pub mod block;
pub mod hardfork;
pub mod keyring;
pub mod registry;

pub use keyring::{
    BlockKeySelection, CanonicalRotationView, EpochKeyConflict, MissingEpochKeys, PurposeKeyring,
    RotationEntry, RotationSchedule, ScheduleError,
};
pub use secp256k1;

/// The purpose keys of one key epoch. The node assembles these from its key
/// custodian (TEE networks) or from the well-known keys (networks with no root
/// key) and threads them into the EVM factories through an epoch-keyed
/// [`PurposeKeyring`].
#[derive(Clone)]
pub struct PurposeKeys {
    /// The network's tx-io keypair: wallets ECDH against the public half to
    /// encrypt calldata, the node decrypts with the secret half. Held as one
    /// keypair so a mismatched pair is unrepresentable.
    pub tx_io: secp256k1::Keypair,
    /// HKDF ikm seeding the RNG precompile. Opaque key material: the
    /// precompile feeds it to HKDF on every call and never interprets it.
    pub rng_ikm: [u8; 64],
}

impl PurposeKeys {
    /// The well-known bundle: what a network with no root key to derive purpose
    /// keys from runs. Published in this org's public repos, so it offers no
    /// confidentiality against anyone who reads the source — its only property
    /// is that every node and client agrees on it.
    ///
    /// Which key source a node boots from is the node's decision; this is the
    /// value it gets when that decision is the well-known keys.
    pub fn well_known() -> Self {
        Self {
            tx_io: seismic_crypto::well_known_tx_io_keypair(),
            rng_ikm: seismic_crypto::well_known_rng_ikm(),
        }
    }
}

/// Redacted: the tx-io secret key and `rng_ikm` are secrets.
impl core::fmt::Debug for PurposeKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PurposeKeys")
            .field("tx_io_pk", &self.tx_io.public_key())
            .finish_non_exhaustive()
    }
}

/// Seismic EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`SeismicEvm`](seismic_revm::SeismicEvm) type.
#[allow(missing_debug_implementations)]
pub struct SeismicEvm<DB: Database, I, P = SeismicPrecompiles<SeismicContext<DB>>> {
    inner: seismic_revm::SeismicEvm<
        SeismicContext<DB>,
        I,
        SeismicInstructions<EthInterpreter, SeismicContext<DB>>,
        P,
    >,
    inspect: bool,
    keyring: std::sync::Arc<PurposeKeyring>,
    selection: Option<Result<BlockKeySelection, KeySelectionError>>,
}

/// Failure to select this execution attempt's keys from its parent state.
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeySelectionError {
    /// No selection has been initialized for this execution attempt.
    #[error("purpose-key selection is uninitialized")]
    Uninitialized,
    /// The authoritative registry could not be read or decoded.
    #[error("could not read parent-state rotation registry: {0}")]
    Registry(String),
    /// Local key material has not been fetched yet.
    #[error(transparent)]
    Missing(#[from] MissingEpochKeys),
}

impl KeySelectionError {
    /// Missing local material is retryable, never a block-validity error.
    pub fn into_block_error(self) -> alloy_evm::block::BlockExecutionError {
        match self {
            Self::Missing(err) => alloy_evm::block::BlockExecutionError::retryable(err),
            err => alloy_evm::block::BlockExecutionError::other(err),
        }
    }
}

impl<DB: Database, I, P> SeismicEvm<DB, I, P> {
    /// Resolve the epoch once from this attempt's database, before any state
    /// changes. Both successful selections and failures are frozen for this EVM.
    /// Raw RPC EVMs use the same path as block execution, without fallback keys.
    pub fn initialize_keys(&mut self) -> Result<&BlockKeySelection, KeySelectionError> {
        if self.selection.is_none() {
            let number = self.inner.0.ctx.block.number.saturating_to();
            let selection = registry::read_schedule(&mut self.inner.0.ctx.journaled_state.database)
                .map_err(KeySelectionError::Registry)
                .and_then(|schedule| {
                    self.keyring
                        .select_epoch(schedule.epoch_at_block(number), number)
                        .map_err(KeySelectionError::Missing)
                });
            if let Ok(selected) = &selection {
                self.inner.0.ctx.chain.set_rng_key(selected.keys.rng_ikm);
            }
            self.selection = Some(selection);
        }
        match &self.selection {
            Some(Ok(selected)) => Ok(selected),
            Some(Err(err)) => Err(err.clone()),
            None => Err(KeySelectionError::Uninitialized),
        }
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &SeismicContext<DB> {
        &self.inner.0.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut SeismicContext<DB> {
        &mut self.inner.0.ctx
    }

    /// Provides a mutable reference to the EVM inspector.
    pub fn inspector_mut(&mut self) -> &mut I {
        &mut self.inner.0.inspector
    }

    /// returns an immutable reference to the EVM precompiles.
    pub fn precompiles(&self) -> &P {
        &self.inner.0.precompiles
    }
}

impl<DB: Database, I, P> SeismicEvm<DB, I, P> {
    /// creates a new [`SeismicEvm`].
    pub fn new(
        inner: seismic_revm::SeismicEvm<
            SeismicContext<DB>,
            I,
            SeismicInstructions<EthInterpreter, SeismicContext<DB>>,
            P,
        >,
        inspect: bool,
        keyring: std::sync::Arc<PurposeKeyring>,
    ) -> Self {
        Self { inner, inspect, keyring, selection: None }
    }
}

impl<DB: Database, I, P> Deref for SeismicEvm<DB, I, P> {
    type Target = SeismicContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, P> DerefMut for SeismicEvm<DB, I, P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, P> Evm for SeismicEvm<DB, I, P>
where
    DB: Database,
    I: Inspector<SeismicContext<DB>>,
    P: PrecompileProvider<SeismicContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = SeismicTransaction<TxEnv>;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SeismicSpecId;
    type Precompiles = P;
    type Inspector = I;

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn block(&self) -> &BlockEnv {
        self.inner.0.block()
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.initialize_keys().map_err(|err| EVMError::Custom(err.to_string()))?;
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact(
        &mut self,
        tx: impl IntoTxEnv<Self::Tx>,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.transact_raw(tx.into_tx_env())
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        let tx = SeismicTransaction {
            base: TxEnv {
                caller,
                kind: TxKind::Call(contract),
                // Explicitly set nonce to 0 so revm does not do any nonce checks
                nonce: 0,
                gas_limit: 30_000_000,
                value: U256::ZERO,
                data,
                // Setting the gas price to zero enforces that no value is transferred as part of
                // the call, and that the call will not count against the block's
                // gas limit
                gas_price: 0,
                // The chain ID check is not relevant here and is disabled if set to None
                chain_id: None,
                // Setting the gas priority fee to None ensures the effective gas price is derived
                // from the `gas_price` field, which we need to be zero
                gas_priority_fee: None,
                access_list: Default::default(),
                // blob fields can be None for this tx
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                tx_type: 0,
                authorization_list: Default::default(),
            },
            tx_hash: Default::default(),
            decryption_failed: false,
        };

        let mut gas_limit = tx.base.gas_limit;
        let mut basefee = 0;
        let mut disable_nonce_check = true;

        // ensure the block gas limit is >= the tx
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // disable the base fee check for this call by setting the base fee to zero
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // disable the nonce check
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        let mut res = self.transact(tx);

        // swap back to the previous gas limit
        core::mem::swap(&mut self.block.gas_limit, &mut gas_limit);
        // swap back to the previous base fee
        core::mem::swap(&mut self.block.basefee, &mut basefee);
        // swap back to the previous nonce check flag
        core::mem::swap(&mut self.cfg.disable_nonce_check, &mut disable_nonce_check);

        // NOTE: We assume that only the contract storage is modified. Revm currently marks the
        // caller and block beneficiary accounts as "touched" when we do the above transact calls,
        // and includes them in the result.
        //
        // We're doing this state cleanup to make sure that changeset only includes the changed
        // contract storage.
        if let Ok(res) = &mut res {
            res.state.retain(|addr, _| *addr == contract);
        }

        res
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        &mut self.journaled_state.database
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context { block: block_env, cfg: cfg_env, journaled_state, .. } = self.inner.0.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn precompiles(&self) -> &Self::Precompiles {
        &self.inner.0.precompiles
    }

    fn precompiles_mut(&mut self) -> &mut Self::Precompiles {
        &mut self.inner.0.precompiles
    }

    fn inspector(&self) -> &Self::Inspector {
        &self.inner.0.inspector
    }

    fn inspector_mut(&mut self) -> &mut Self::Inspector {
        &mut self.inner.0.inspector
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.0.ctx.journaled_state.database,
            &self.inner.0.inspector,
            &self.inner.0.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.0.ctx.journaled_state.database,
            &mut self.inner.0.inspector,
            &mut self.inner.0.precompiles,
        )
    }
}

/// Factory producing [`SeismicEvm`]s.
///
/// Key selection is lazy and fallible: the block executor initializes it before
/// pre-execution changes, and raw RPC EVMs initialize before their first transaction.
/// Neither path uses canonical metadata or substitutes keys from another epoch.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SeismicEvmFactory {
    keyring: std::sync::Arc<PurposeKeyring>,
}

impl SeismicEvmFactory {
    /// Creates a new [`SeismicEvmFactory`] reading the given keyring.
    pub fn new(keyring: std::sync::Arc<PurposeKeyring>) -> Self {
        Self { keyring }
    }

    /// Create an EVM using the keyring's RNG ikm for the block in `input`.
    pub fn create_evm_with_rng_key<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
    ) -> SeismicEvm<DB, NoOpInspector> {
        let context = self.uninitialized_context();

        SeismicEvm {
            inner: context
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_evm_with_inspector(NoOpInspector {}),
            inspect: false,
            keyring: self.keyring.clone(),
            selection: None,
        }
    }

    // This placeholder is never used by transaction execution: initialize_keys
    // must succeed first, replacing it with the parent-state-selected key.
    fn uninitialized_context(&self) -> SeismicContext<EmptyDB> {
        SeismicContext::seismic_with_rng_key([0; 64])
    }

    /// Create an EVM with inspector using the keyring's RNG ikm for the block in
    /// `input`.
    pub fn create_evm_with_inspector_and_rng_key<DB: Database, I: Inspector<SeismicContext<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        inspector: I,
    ) -> SeismicEvm<DB, I> {
        let context = self.uninitialized_context();

        SeismicEvm {
            inner: context
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_evm_with_inspector(inspector),
            inspect: true,
            keyring: self.keyring.clone(),
            selection: None,
        }
    }
}

impl EvmFactory for SeismicEvmFactory {
    type Evm<DB: Database, I: Inspector<SeismicContext<DB>>> = SeismicEvm<DB, I>;
    type Context<DB: Database> = SeismicContext<DB>;
    type Tx = SeismicTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, InvalidTransaction>;
    type HaltReason = HaltReason;
    type Spec = SeismicSpecId;
    type Precompiles<DB: Database> = SeismicPrecompiles<Self::Context<DB>>;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
    ) -> Self::Evm<DB, NoOpInspector> {
        self.create_evm_with_rng_key(db, input)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        self.create_evm_with_inspector_and_rng_key(db, input, inspector)
    }
}
