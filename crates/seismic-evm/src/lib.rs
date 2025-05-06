#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_evm::eth::EthEvmContext;
use alloy_evm::IntoTxEnv;
use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_evm::EthEvm;
use alloy_primitives::{Address, Bytes};
use core::fmt::Debug;
use revm::MainBuilder;
use revm::MainContext;
use revm::{
    context::{BlockEnv, TxEnv, Cfg},
    context_interface::result::{EVMError, HaltReason, ResultAndState},
    context_interface::ContextTr,
    handler::EthPrecompiles,
    handler::PrecompileProvider,
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    primitives::hardfork::SpecId,
    Context, Inspector,
};

/// Seismic EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`SeismicEvm`](seismic_revm::SeismicEvm) type.
#[allow(missing_debug_implementations)]
pub struct SeismicEvm<DB: Database, I, PRECOMPILE = EthPrecompiles> {
    inner: EthEvm<DB, I, PRECOMPILE>,
}

// impl<DB: Database, I, P> SeismicEvm<DB, I, P> {
//     /// Provides a reference to the EVM context.
//     pub const fn ctx(&self) -> &SeismicContext<DB> {
//         &self.inner.0.data.ctx
//     }

//     /// Provides a mutable reference to the EVM context.
//     pub fn ctx_mut(&mut self) -> &mut SeismicContext<DB> {
//         &mut self.inner.0.data.ctx
//     }

//     /// Provides a mutable reference to the EVM inspector.
//     pub fn inspector_mut(&mut self) -> &mut I {
//         &mut self.inner.0.data.inspector
//     }
// }

impl<DB: Database, I, PRECOMPILE> SeismicEvm<DB, I, PRECOMPILE> {
    /// creates a new [`SeismicEvm`].
    pub fn new(inner: EthEvm<DB, I, PRECOMPILE>) -> Self {
        Self { inner }
    }
}

// impl<DB: Database, I, P> Deref for OpEvm<DB, I, P> {
//     type Target = OpContext<DB>;

//     #[inline]
//     fn deref(&self) -> &Self::Target {
//         self.ctx()
//     }
// }

// impl<DB: Database, I, P> DerefMut for OpEvm<DB, I, P> {
//     #[inline]
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         self.ctx_mut()
//     }
// }

impl<DB, I, PRECOMPILE> Evm for SeismicEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
    PRECOMPILE: PrecompileProvider<EthEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }

    fn transact_raw(&mut self, tx: Self::Tx) -> Result<ResultAndState, Self::Error> {
        self.inner.transact_raw(tx)
    }

    fn transact(
        &mut self,
        tx: impl IntoTxEnv<Self::Tx>,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // attention: ENCRYPT and DECRYPT HERE
        self.transact_raw(tx.into_tx_env())
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        self.inner.db_mut()
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled);
    }
}

/// Custom EVM configuration.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicEvmFactory;

impl EvmFactory for SeismicEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        SeismicEvm<DB, I, CustomPrecompiles>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(CustomPrecompiles::new());

        let ethevm = EthEvm::new(evm, false);
        SeismicEvm::new(ethevm)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let ethevm = EthEvm::new(
            self.create_evm(db, input).inner.into_inner().with_inspector(inspector),
            true,
        );
        SeismicEvm::new(ethevm)
    }
}

/// A custom precompile that contains static precompiles.
#[derive(Clone, Debug)]
pub struct CustomPrecompiles {
    pub precompiles: EthPrecompiles,
}

impl CustomPrecompiles {
    /// Given a [`PrecompileProvider`] and cache for a specific precompiles, create a
    /// wrapper that can be used inside Evm.
    fn new() -> Self {
        Self { precompiles: EthPrecompiles::default() }
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for CustomPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.precompiles, spec);
    }

    fn run(
        &mut self,
        _context: &mut CTX,
        address: &Address,
        bytes: &Bytes,
        gas_limit: u64,
    ) -> Result<Option<InterpreterResult>, String> {
        self.precompiles.run(_context, address, bytes, gas_limit)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.precompiles.warm_addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.precompiles.contains(address)
    }
}
