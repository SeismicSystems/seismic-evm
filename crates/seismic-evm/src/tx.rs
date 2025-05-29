//! Transaction type for the seismic-evm crate
//!
//! Works as an intermediary between SeismicTransactionSigned for consensus
//! and SeismicTransaction<TxEnv> for seismic-revm

use alloy_evm::FromRecoveredTx;
use alloy_evm::IntoTxEnv;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use revm::context::{Transaction, TxEnv};
use seismic_alloy_consensus::SeismicTxEnvelope;
use seismic_alloy_consensus::{
    InputDecryptionElements, InputDecryptionElementsError, TxSeismicElements,
};
use seismic_revm::transaction::abstraction::SeismicTransaction;

/// Tx type for the seismic-evm crate SeismicEvm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeismicEvmSeismicEvmTx {
    /// inner tx
    pub tx: SeismicTransaction<TxEnv>,
    /// stuff to help a client decrypt the tx
    pub decryption_elements: Option<TxSeismicElements>,
}

impl IntoTxEnv<Self> for SeismicEvmSeismicEvmTx {
    fn into_tx_env(self) -> Self {
        self
    }
}

impl Transaction for SeismicEvmSeismicEvmTx {
    type AccessListItem = <TxEnv as revm::context_interface::Transaction>::AccessListItem;
    type Authorization = <TxEnv as revm::context_interface::Transaction>::Authorization;

    fn tx_type(&self) -> u8 {
        self.tx.tx_type()
    }

    fn caller(&self) -> Address {
        self.tx.caller()
    }

    fn gas_limit(&self) -> u64 {
        self.tx.gas_limit()
    }

    fn value(&self) -> U256 {
        self.tx.value()
    }

    fn input(&self) -> &Bytes {
        self.tx.input()
    }

    fn nonce(&self) -> u64 {
        self.tx.nonce()
    }

    fn kind(&self) -> TxKind {
        self.tx.kind()
    }

    fn chain_id(&self) -> Option<u64> {
        self.tx.chain_id()
    }

    fn access_list(&self) -> Option<impl Iterator<Item = &Self::AccessListItem>> {
        self.tx.access_list()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.tx.max_priority_fee_per_gas()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.tx.max_fee_per_gas()
    }

    fn gas_price(&self) -> u128 {
        self.tx.gas_price()
    }

    fn blob_versioned_hashes(&self) -> &[B256] {
        self.tx.blob_versioned_hashes()
    }

    fn max_fee_per_blob_gas(&self) -> u128 {
        self.tx.max_fee_per_blob_gas()
    }

    fn effective_gas_price(&self, base_fee: u128) -> u128 {
        self.tx.effective_gas_price(base_fee)
    }

    fn authorization_list_len(&self) -> usize {
        self.tx.authorization_list_len()
    }

    fn authorization_list(&self) -> impl Iterator<Item = &Self::Authorization> {
        self.tx.authorization_list()
    }
}

impl InputDecryptionElements for SeismicEvmSeismicEvmTx {
    fn get_decryption_elements(&self) -> Result<TxSeismicElements, InputDecryptionElementsError> {
        self.decryption_elements.clone().ok_or(InputDecryptionElementsError::NoElements)
    }

    fn get_input(&self) -> &Bytes {
        self.tx.input()
    }

    fn set_input(&mut self, data: Bytes) -> Result<(), InputDecryptionElementsError> {
        let mut base = self.tx.base.clone();
        base.data = data;
        self.tx.base = base;
        Ok(())
    }
}

impl FromRecoveredTx<SeismicTxEnvelope> for SeismicEvmSeismicEvmTx {
    fn from_recovered_tx(tx: &SeismicTxEnvelope, sender: Address) -> Self {
        let inner_env: SeismicTransaction<TxEnv> =
            SeismicTransaction::<TxEnv>::from_recovered_tx(&tx, sender);

        let decryption_elements = match tx.get_decryption_elements() {
            Ok(elements) => Some(elements),
            Err(_) => None,
        };

        Self { tx: inner_env, decryption_elements }
    }
}
