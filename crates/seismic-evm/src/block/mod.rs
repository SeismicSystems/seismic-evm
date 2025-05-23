//! Block executor for Seismic.

use crate::hardfork::{SeismicChainHardforks, SeismicHardforks};
use crate::SeismicEvmFactory;
use alloy_consensus::{transaction::Recovered, Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_evm::eth::receipt_builder::ReceiptBuilder;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_evm::eth::EthBlockExecutor;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, OnStateHook,
    },
    Database, Evm, EvmFactory, FromRecoveredTx,
};
use alloy_primitives::Log;
pub use receipt_builder::SeismicAlloyReceiptBuilder;
use revm::{database::State, Inspector};

pub mod receipt_builder;

type SeismicBlockExecutionCtx<'a> = EthBlockExecutionCtx<'a>;

/// Block executor for Seismic.
#[derive(Debug)]
pub struct SeismicBlockExecutor<'a, Evm, Spec, R>
where
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
{
    inner: EthBlockExecutor<'a, Evm, Spec, R>,
}

impl<'a, E, Spec, R> SeismicBlockExecutor<'a, E, Spec, R>
where
    E: Evm,
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
    Spec: SeismicHardforks + Clone,
{
    /// Creates a new [`SeismicBlockExecutor`].
    pub fn new(evm: E, ctx: SeismicBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self {
        Self { inner: EthBlockExecutor::new(evm, ctx, spec, receipt_builder) }
    }
}

impl<'db, DB, E, Spec, R> BlockExecutor for SeismicBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx: FromRecoveredTx<R::Transaction>>,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: Recovered<&Self::Transaction>,
        f: impl FnOnce(&revm::context::result::ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        self.inner.execute_transaction_with_result_closure(tx, f)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
}

/// Ethereum block executor factory.
#[derive(Debug, Clone, Default, Copy)]
pub struct SeismicBlockExecutorFactory<
    R = SeismicAlloyReceiptBuilder,
    Spec = SeismicChainHardforks,
    EvmFactory = SeismicEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmFactory> SeismicBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`SeismicReceiptBuilder`].
    pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
        Self { receipt_builder, spec, evm_factory }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Exposes the EVM factory.
    pub const fn evm_factory(&self) -> &EvmFactory {
        &self.evm_factory
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for SeismicBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: SeismicHardforks + EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction>>,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = SeismicBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<EvmF::Context<&'a mut State<DB>>> + 'a,
    {
        SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder)
    }
}
