// //! Block executor for Seismic.

// use crate::SeismicEvmFactory;
// use alloy_consensus::{transaction::Recovered, Eip658Value, Header, Transaction, TxReceipt};
// use alloy_eips::{Encodable2718, Typed2718};
// use alloy_evm::{
//     block::{
//         state_changes::{balance_increment_state, post_block_balance_increments},
//         BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
//         BlockExecutorFor, BlockValidationError, OnStateHook, StateChangePostBlockSource,
//         StateChangeSource, SystemCaller,
//     },
//     eth::receipt_builder::ReceiptBuilderCtx,
//     Database, Evm, EvmFactory, FromRecoveredTx,
// };
// use alloy_seismic_hardforks::{SeismicChainHardforks, SeismicHardforks};
// use alloy_hardforks::ChainHardforks;
// use alloy_primitives::{Bytes, B256};
// // pub use receipt_builder::SeismicAlloyReceiptBuilder;
// // use receipt_builder::SeismicReceiptBuilder;
// use revm::{context::result::ResultAndState, database::State, DatabaseCommit, Inspector};

// // mod canyon;
// // pub mod receipt_builder;

// /// Context for OP block execution.
// #[derive(Debug, Clone)]
// pub struct SeismicBlockExecutionCtx {
//     /// Parent block hash.
//     pub parent_hash: B256,
//     /// Parent beacon block root.
//     pub parent_beacon_block_root: Option<B256>,
//     /// The block's extra data.
//     pub extra_data: Bytes,
// }

// /// Block executor for Seismic.
// #[derive(Debug)]
// pub struct SeismicBlockExecutor<Evm, R: SeismicReceiptBuilder, Spec> {
//     /// Spec.
//     spec: Spec,
//     /// Receipt builder.
//     receipt_builder: R,

//     /// Context for block execution.
//     ctx: SeismicBlockExecutionCtx,
//     /// The EVM used by executor.
//     evm: Evm,
//     /// Receipts of executed transactions.
//     receipts: Vec<R::Receipt>,
//     /// Total gas used by executed transactions.
//     gas_used: u64,
//     /// Whether Regolith hardfork is active.
//     is_regolith: bool,
//     /// Utility to call system smart contracts.
//     system_caller: SystemCaller<Spec>,
// }

// impl<E, R, Spec> SeismicBlockExecutor<E, R, Spec>
// where
//     E: Evm,
//     R: SeismicReceiptBuilder,
//     Spec: SeismicHardforks + Clone,
// {
//     /// Creates a new [`SeismicBlockExecutor`].
//     pub fn new(evm: E, ctx: SeismicBlockExecutionCtx, spec: Spec, receipt_builder: R) -> Self {
//         Self {
//             is_regolith: spec.is_regolith_active_at_timestamp(evm.block().timestamp),
//             evm,
//             system_caller: SystemCaller::new(spec.clone()),
//             spec,
//             receipt_builder,
//             receipts: Vec::new(),
//             gas_used: 0,
//             ctx,
//         }
//     }
// }

// impl<'db, DB, E, R, Spec> BlockExecutor for SeismicBlockExecutor<E, R, Spec>
// where
//     DB: Database + 'db,
//     E: Evm<DB = &'db mut State<DB>, Tx: FromRecoveredTx<R::Transaction>>,
//     R: SeismicReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
//     Spec: SeismicHardforks,
// {
//     type Transaction = R::Transaction;
//     type Receipt = R::Receipt;
//     type Evm = E;

//     fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
//         unimplemented!()
//     }

//     fn execute_transaction_with_result_closure(
//         &mut self,
//         tx: Recovered<&Self::Transaction>,
//         f: impl FnOnce(&revm::context::result::ExecutionResult<<Self::Evm as Evm>::HaltReason>),
//     ) -> Result<u64, BlockExecutionError> {
//         unimplemented!()
//     }

//     fn finish(
//         mut self,
//     ) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
//         unimplemented!()
//     }

//     fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
//        unimplemented!()
//     }

//     fn evm_mut(&mut self) -> &mut Self::Evm {
//        unimplemented!()
//     }
// }

// /// Ethereum block executor factory.
// #[derive(Debug, Clone, Default, Copy)]
// pub struct SeismicBlockExecutorFactory<
//     R = SeismicAlloyReceiptBuilder,
//     Spec = ChainHardforks,
//     EvmFactory = SeismicEvmFactory,
// > {
//     /// Receipt builder.
//     receipt_builder: R,
//     /// Chain specification.
//     spec: Spec,
//     /// EVM factory.
//     evm_factory: EvmFactory,
// }

// impl<R, Spec, EvmFactory> SeismicBlockExecutorFactory<R, Spec, EvmFactory> {
//     /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
//     /// [`SeismicReceiptBuilder`].
//     pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
//         Self { receipt_builder, spec, evm_factory }
//     }

//     /// Exposes the receipt builder.
//     pub const fn receipt_builder(&self) -> &R {
//         &self.receipt_builder
//     }

//     /// Exposes the chain specification.
//     pub const fn spec(&self) -> &Spec {
//         &self.spec
//     }

//     /// Exposes the EVM factory.
//     pub const fn evm_factory(&self) -> &EvmFactory {
//         &self.evm_factory
//     }
// }

// impl<R, Spec, EvmF> BlockExecutorFactory for SeismicBlockExecutorFactory<R, Spec, EvmF>
// where
//     R: SeismicReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
//     Spec: SeismicHardforks,
//     EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction>>,
//     Self: 'static,
// {
//     type EvmFactory = EvmF;
//     type ExecutionCtx<'a> = SeismicBlockExecutionCtx;
//     type Transaction = R::Transaction;
//     type Receipt = R::Receipt;

//     fn evm_factory(&self) -> &Self::EvmFactory {
//         &self.evm_factory
//     }

//     fn create_executor<'a, DB, I>(
//         &'a self,
//         evm: EvmF::Evm<&'a mut State<DB>, I>,
//         ctx: Self::ExecutionCtx<'a>,
//     ) -> impl BlockExecutorFor<'a, Self, DB, I>
//     where
//         DB: Database + 'a,
//         I: Inspector<EvmF::Context<&'a mut State<DB>>> + 'a,
//     {
//         SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder)
//     }
// }
