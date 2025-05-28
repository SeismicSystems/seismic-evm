//! Custom receipt builder for Seismic.

use alloy_consensus::Eip658Value;
use alloy_evm::{
    eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    Evm,
};
use seismic_alloy_consensus::{SeismicReceiptEnvelope, SeismicTxEnvelope, SeismicTxType};

/// Receipt builder operating on seismic alloy types. Useful for testing,
/// but reth uses SeismicRethReceiptBuilder instead with T = SeismicTransactionSigned
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicAlloyReceiptBuilder;

impl ReceiptBuilder for SeismicAlloyReceiptBuilder {
    type Transaction = SeismicTxEnvelope;
    type Receipt = SeismicReceiptEnvelope;

    fn build_receipt<'a, E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'a, Self::Transaction, E>,
    ) -> Self::Receipt {
        let receipt_with_bloom = alloy_consensus::Receipt {
            status: Eip658Value::Eip658(ctx.result.is_success()),
            cumulative_gas_used: ctx.cumulative_gas_used,
            logs: ctx.result.into_logs(),
        }
        .with_bloom();

        let ty = ctx.tx.tx_type();

        match ty {
            SeismicTxType::Legacy => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
            SeismicTxType::Eip2930 => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
            SeismicTxType::Eip1559 => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
            SeismicTxType::Eip7702 => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
            SeismicTxType::Seismic => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}
