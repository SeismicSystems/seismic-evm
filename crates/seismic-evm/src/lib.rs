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
#[allow(unused_imports)]
use revm::{
    context::{result::InvalidTransaction, BlockEnv, TxEnv},
    context_interface::{
        result::{EVMError, ResultAndState},
        ContextTr,
    },
    database_interface::EmptyDB,
    handler::PrecompileProvider,
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    Context, ExecuteEvm, InspectEvm, Inspector,
};
use seismic_enclave::rpc::SyncEnclaveApiClientBuilder;
use seismic_revm::{
    instructions::instruction_provider::SeismicInstructions,
    precompiles::SeismicPrecompiles,
    transaction::abstraction::{RngMode, SeismicTransaction},
    SeismicBuilder, SeismicContext, SeismicHaltReason, SeismicSpecId,
};

#[cfg(feature = "no-value-transfers")]
use seismic_revm::NoValueTransferInspector;

pub mod block;
pub mod hardfork;

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
}

impl<DB: Database, I, P> SeismicEvm<DB, I, P> {
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
    ) -> Self {
        Self { inner, inspect }
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
    type HaltReason = SeismicHaltReason;
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
            rng_mode: RngMode::Execution,
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
#[derive(Debug, Clone)]
#[non_exhaustive]
// Factory that creates SeismicEVMs with a pre-fetched RNG key.
// The live key is provided by SeismicEvmConfig and gets wired into SeismicChain for Execute mode
// transactions.
pub struct SeismicEvmFactory<T: SyncEnclaveApiClientBuilder> {
    live_rng_key: Option<schnorrkel::Keypair>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: SyncEnclaveApiClientBuilder> Default for SeismicEvmFactory<T> {
    fn default() -> Self {
        Self::new_with_rng_key(None)
    }
}

impl<T: SyncEnclaveApiClientBuilder> SeismicEvmFactory<T> {
    /// Creates a new [`SeismicEvmFactory`] with a pre-fetched RNG key.
    /// This is the preferred constructor when the RNG key is managed at a higher level (e.g.,
    /// SeismicEvmConfig).
    pub fn new_with_rng_key(live_rng_key: Option<schnorrkel::Keypair>) -> Self {
        Self { live_rng_key, _phantom: std::marker::PhantomData }
    }

    /// Creates a new [`SeismicEvmFactory`] with enclave client (legacy compatibility).
    /// This method fetches the RNG key on each EVM creation, which is less efficient.
    /// Prefer using `new_with_rng_key` with a pre-fetched key when possible.
    pub fn new(enclave_client_builder: T) -> Self {
        let enclave_client = enclave_client_builder.build();
        let live_rng_key = Self::get_live_rng_key_from_enclave_client(&enclave_client);
        Self::new_with_rng_key(live_rng_key)
    }

    /// Get the live RNG key from an enclave client
    fn get_live_rng_key_from_enclave_client(
        enclave_client: &T::Client,
    ) -> Option<schnorrkel::Keypair> {
        use seismic_enclave::{keys::GetPurposeKeysRequest, rpc::SyncEnclaveApiClient};

        let request = GetPurposeKeysRequest { epoch: 0 };

        match enclave_client.get_purpose_keys(request) {
            Ok(response) => Some(response.rng_keypair),
            Err(_) => None,
        }
    }

    /// Create an EVM with an optional RNG keypair.
    /// If no keypair is provided, uses the pre-fetched live RNG key from SeismicEvmConfig.
    pub fn create_evm_with_rng_key<DB, INSP>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        rng_keypair: Option<schnorrkel::Keypair>,
        inspector: INSP,
    ) -> SeismicEvm<DB, INSP>
    where
        DB: Database,
        INSP: Inspector<SeismicContext<DB>>,
    {
        let live_key = rng_keypair.or_else(|| self.live_rng_key.clone());
        let context = self.create_context_with_rng_key(live_key);

        SeismicEvm {
            inner: context
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_evm_with_inspector(inspector),
            inspect: false,
        }
    }

    /// Create SeismicContext with appropriate RNG key
    fn create_context_with_rng_key(
        &self,
        live_key: Option<schnorrkel::Keypair>,
    ) -> SeismicContext<EmptyDB> {
        use seismic_revm::DefaultSeismicContext;

        match live_key {
            Some(keypair) => SeismicContext::seismic_with_rng_key(keypair),
            None => SeismicContext::seismic(),
        }
    }

    /// Create an EVM with inspector and optional RNG keypair.
    pub fn create_evm_with_inspector_and_rng_key<DB: Database, I: Inspector<SeismicContext<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        inspector: I,
        rng_keypair: Option<schnorrkel::Keypair>,
    ) -> SeismicEvm<DB, I> {
        let live_key = rng_keypair.or_else(|| self.live_rng_key.clone());

        let context = self.create_context_with_rng_key(live_key);

        SeismicEvm {
            inner: context
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_seismic_evm_with_inspector(inspector),
            inspect: true,
        }
    }
}

impl<T: SyncEnclaveApiClientBuilder> EvmFactory for SeismicEvmFactory<T> {
    type Evm<DB: Database, I: Inspector<SeismicContext<DB>>> = SeismicEvm<DB, I>;
    type Context<DB: Database> = SeismicContext<DB>;
    type Tx = SeismicTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, InvalidTransaction>;
    type HaltReason = SeismicHaltReason;
    type Spec = SeismicSpecId;
    type Precompiles<DB: Database> = SeismicPrecompiles<Self::Context<DB>>;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
    ) -> Self::Evm<DB, Box<dyn Inspector<SeismicContext<DB>>>> {
        #[cfg(not(feature = "no-value-transfers"))]
        let inspector = Box::new(NoOpInspector {});
        #[cfg(feature = "no-value-transfers")]
        let inspector = Box::new(NoValueTransferInspector {});

        self.create_evm_with_rng_key(db, input, None, inspector)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<SeismicSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        self.create_evm_with_inspector_and_rng_key(db, input, inspector, None)
    }
}
