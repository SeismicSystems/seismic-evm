#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_evm::eth::EthEvmContext;
use alloy_evm::EthEvm;
use alloy_evm::IntoTxEnv;
use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_primitives::address;
use alloy_primitives::{Address, Bytes};
use seismic_revm::DefaultSeismic;
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use revm::MainBuilder;
use revm::MainContext;
use revm::{
    context::{BlockEnv, Cfg, TxEnv},
    context_interface::result::{EVMError, HaltReason, ResultAndState},
    context_interface::ContextTr,
    handler::EthPrecompiles,
    handler::PrecompileProvider,
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    precompile::{PrecompileFn, PrecompileOutput, PrecompileResult, Precompiles},
    primitives::hardfork::SpecId,
    Context, Inspector,
};
use std::sync::OnceLock;
use seismic_revm::{SeismicContext, SeismicSpecId};
use revm::handler::EvmTr;
use revm::ExecuteEvm;
use seismic_revm::SeismicHaltReason;
use seismic_revm::transaction::abstraction::SeismicTransaction;

/// Seismic EVM implementation.
///
/// This is a wrapper type around the `revm` evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`SeismicEvm`](seismic_revm::SeismicEvm) type.
#[allow(missing_debug_implementations)]
pub struct SeismicEvm<DB: Database, I> {
    inner: seismic_revm::SeismicEvm<SeismicContext<DB>, I>,
    inspect: bool,
}

impl<DB: Database + revm::database_interface::Database, I> SeismicEvm<DB, I> {
    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &SeismicContext<DB> {
        &self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut SeismicContext<DB> {
        &mut self.inner.0.data.ctx
    }

    /// Provides a mutable reference to the EVM inspector.
    pub fn inspector_mut(&mut self) -> &mut I {
        &mut self.inner.0.data.inspector
    }
}

impl<DB: Database, I> SeismicEvm<DB, I> {
    /// creates a new [`SeismicEvm`].
    pub fn new(inner: seismic_revm::SeismicEvm<SeismicContext<DB>, I>, inspect: bool,
    ) -> Self {
        Self { inner, inspect }
    }
}

impl<DB: Database, I> Deref for SeismicEvm<DB, I> {
    type Target = SeismicContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I> DerefMut for SeismicEvm<DB, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I> Evm for SeismicEvm<DB, I>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
    // PRECOMPILE: PrecompileProvider<EthEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = SeismicTransaction<TxEnv>;
    type Error = EVMError<DB::Error>;
    type HaltReason = SeismicHaltReason;
    type Spec = SeismicSpecId;

    fn block(&self) -> &BlockEnv {
        self.inner.0.block()
    }

    fn transact_raw(&mut self, tx: Self::Tx) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.set_tx(tx);
            self.inner.inspect_replay()
        } else {
            self.inner.transact(tx)
        }
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
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        &mut self.journaled_state.database
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context { block: block_env, cfg: cfg_env, journaled_state, .. } = self.inner.0.data.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }
}

/// Custom EVM configuration.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SeismicEvmFactory;

impl EvmFactory for SeismicEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        SeismicEvm<DB, I>;
    type Tx = SeismicTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = SeismicHaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SeismicSpecId;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv<SeismicSpecId>) -> Self::Evm<DB, NoOpInspector> {
        SeismicEvm {
            inner: Context::seismic()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_op_with_inspector(NoOpInspector {}),
            inspect: false,
        }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        SeismicEvm {
            inner: Context::seismic()
                .with_db(db)
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .build_op_with_inspector(inspector),
            inspect: true,
        }
    }
}

// /// A custom precompile that contains static precompiles.
// #[derive(Clone, Debug)]
// pub struct CustomPrecompiles {
//     pub precompiles: EthPrecompiles,
// }

// impl CustomPrecompiles {
//     /// Given a [`PrecompileProvider`] and cache for a specific precompiles, create a
//     /// wrapper that can be used inside Evm.
//     fn new() -> Self {
//         Self { precompiles: EthPrecompiles::default() }
//     }
// }

// impl<CTX: ContextTr> PrecompileProvider<CTX> for CustomPrecompiles {
//     type Output = InterpreterResult;

//     fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) {
//         let spec_id = spec.clone().into();
//         if spec_id == SpecId::PRAGUE {
//             self.precompiles = EthPrecompiles { precompiles: prague_custom() }
//         } else {
//             PrecompileProvider::<CTX>::set_spec(&mut self.precompiles, spec);
//         }
//     }

//     fn run(
//         &mut self,
//         context: &mut CTX,
//         address: &Address,
//         bytes: &Bytes,
//         gas_limit: u64,
//     ) -> Result<Option<Self::Output>, String> {
//         self.precompiles.run(context, address, bytes, gas_limit)
//     }

//     fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
//         self.precompiles.warm_addresses()
//     }

//     fn contains(&self, address: &Address) -> bool {
//         self.precompiles.contains(address)
//     }
// }

// /// Returns precompiles for Fjor spec.
// pub fn prague_custom() -> &'static Precompiles {
//     static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
//     INSTANCE.get_or_init(|| {
//         let mut precompiles = Precompiles::prague().clone();
//         // Custom precompile.
//         precompiles.extend([(
//             address!("0x0000000000000000000000000000000000000999"),
//             |_, _| -> PrecompileResult {
//                 PrecompileResult::Ok(PrecompileOutput::new(0, Bytes::new()))
//             } as PrecompileFn,
//         )
//             .into()]);
//         precompiles
//     })
// }
