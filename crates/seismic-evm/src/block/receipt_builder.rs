// use alloy_consensus::Eip658Value;
// use alloy_evm::{eth::receipt_builder::ReceiptBuilderCtx, Evm};
// use seismic_alloy_consensus::{SeismicReceiptEnvelope, SeismicTxEnvelope, SeismicTxType};

// /// Builds an [`SeismicTransactionReceipt`].
// ///
// /// Like [`EthReceiptBuilder`], but with Seismic types
// #[derive(Debug)]
// pub struct SeismicReceiptBuilder {
//     /// The base response body, contains L1 fields.
//     pub base: SeismicTransactionReceipt,
// }

// impl SeismicReceiptBuilder {
//     /// Returns a new builder.
//     pub fn new(
//         transaction: &SeismicTransactionSigned,
//         meta: TransactionMeta,
//         receipt: &SeismicReceipt,
//         all_receipts: &[SeismicReceipt],
//         blob_params: Option<BlobParams>,
//     ) -> Result<Self, EthApiError> {
//         let base = build_receipt(
//             transaction,
//             meta,
//             receipt,
//             all_receipts,
//             blob_params,
//             |receipt_with_bloom| match receipt.tx_type() {
//                 SeismicTxType::Legacy => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
//                 SeismicTxType::Eip2930 => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
//                 SeismicTxType::Eip1559 => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
//                 SeismicTxType::Eip7702 => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
//                 SeismicTxType::Seismic => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
//                 #[allow(unreachable_patterns)]
//                 _ => unreachable!(),
//             },
//         )?;

//         Ok(Self { base })
//     }

//     /// Builds [`SeismicTransactionReceipt`] by combing core (l1) receipt fields and additional OP
//     /// receipt fields.
//     pub fn build(self) -> SeismicTransactionReceipt {
//         self.base
//     }
// }