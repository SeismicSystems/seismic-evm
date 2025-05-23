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
use alloy_evm::block::InternalBlockExecutionError;
use seismic_alloy_consensus::InputDecryptionElements;
use seismic_enclave::client::rpc::SyncEnclaveApiClient;

type SeismicBlockExecutionCtx<'a> = EthBlockExecutionCtx<'a>;

/// Block executor for Seismic.
#[derive(Debug)]
pub struct SeismicBlockExecutor<'a, Evm, Spec, R, C>
where
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
{
    inner: EthBlockExecutor<'a, Evm, Spec, R>,
    enclave_client: C,
}

impl<'a, E, Spec, R, C> SeismicBlockExecutor<'a, E, Spec, R, C>
where
    E: Evm,
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
    Spec: SeismicHardforks + Clone,
{
    /// Creates a new [`SeismicBlockExecutor`].
    pub fn new(
        evm: E,
        ctx: SeismicBlockExecutionCtx<'a>,
        spec: Spec,
        receipt_builder: R,
        enclave_client: C,
    ) -> Self {
        Self { inner: EthBlockExecutor::new(evm, ctx, spec, receipt_builder), enclave_client }
    }
}

impl<'db, DB, E, Spec, R, C> BlockExecutor for SeismicBlockExecutor<'_, E, Spec, R, C>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx: FromRecoveredTx<R::Transaction>>,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements + Clone,
        Receipt: TxReceipt<Log = Log>,
    >,
    C: SyncEnclaveApiClient,
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
        println!("seismic_block_executor: execute_transaction_with_result_closure: tx: {:?}", tx);
        let mut tx = tx.clone();
        let inner_ptr = tx.inner_mut();
        let mut inner_for_decryption = inner_ptr.clone();

        // case where there are seismic elements in the tx,
        // meaning it is encrypted and we need to decrypt it
        if let Ok(seismic_elements) = inner_for_decryption.get_decryption_elements() {
            let ciphertext = inner_for_decryption.input().clone();
            let decrypted_data = seismic_elements
                .server_decrypt(&self.enclave_client, &ciphertext)
                .map_err(|e| InternalBlockExecutionError::Other(Box::new(e)))?;
            inner_for_decryption.set_input(decrypted_data).unwrap();
            *inner_ptr = &inner_for_decryption;
        }

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
    C,
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
    /// Enclave client.
    enclave_client: C,
}

impl<C, R, Spec, EvmFactory> SeismicBlockExecutorFactory<C, R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`SeismicReceiptBuilder`].
    pub const fn new(
        receipt_builder: R,
        spec: Spec,
        evm_factory: EvmFactory,
        enclave_client: C,
    ) -> Self {
        Self { receipt_builder, spec, evm_factory, enclave_client }
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

impl<C, R, Spec, EvmF> BlockExecutorFactory for SeismicBlockExecutorFactory<C, R, Spec, EvmF>
where
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements + Clone,
        Receipt: TxReceipt<Log = Log>,
    >,
    Spec: SeismicHardforks + EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction>>,
    C: SyncEnclaveApiClient + Clone,
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
        let enclave_client = self.enclave_client.clone();
        SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder, enclave_client)
    }
}
