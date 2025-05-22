use alloy_consensus::Eip658Value;
use alloy_evm::{eth::receipt_builder::ReceiptBuilderCtx, Evm};
use seismic_alloy_consensus::{SeismicReceiptEnvelope, SeismicTxEnvelope, SeismicTxType};

/// Type that knows how to build a receipt based on execution result.
#[auto_impl::auto_impl(&, Arc)]
pub trait SeismicReceiptBuilder {
    /// Transaction type.
    type Transaction;
    /// Receipt type.
    type Receipt;

    /// Builds a receipt given a transaction and the result of the execution.
    ///
    /// Note: this method should return `Err` if the transaction is a deposit transaction. In that
    /// case, the `build_deposit_receipt` method will be called.
    #[expect(clippy::result_large_err)] // Err(_) is always consumed
    fn build_receipt<'a, E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'a, Self::Transaction, E>,
    ) -> Result<Self::Receipt, ReceiptBuilderCtx<'a, Self::Transaction, E>>;
}

/// Receipt builder operating on op-alloy types.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicAlloyReceiptBuilder;

impl SeismicReceiptBuilder for SeismicAlloyReceiptBuilder {
    type Transaction = SeismicTxEnvelope;
    type Receipt = SeismicReceiptEnvelope;

    fn build_receipt<'a, E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'a, Self::Transaction, E>,
    ) -> Result<Self::Receipt, ReceiptBuilderCtx<'a, Self::Transaction, E>> {
        let receipt = alloy_consensus::Receipt {
            status: Eip658Value::Eip658(ctx.result.is_success()),
            cumulative_gas_used: ctx.cumulative_gas_used,
            logs: ctx.result.into_logs(),
        }
        .with_bloom();

        let ty = ctx.tx.tx_type();

        Ok(match ty {
            SeismicTxType::Legacy => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
            SeismicTxType::Eip2930 => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
            SeismicTxType::Eip1559 => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
            SeismicTxType::Eip7702 => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
            SeismicTxType::Seismic => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        })
    }
}
