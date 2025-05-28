//! Abstraction of an executable transaction.

use alloy_consensus::{transaction::Recovered, Transaction};
use alloy_eips::{
    eip2718::{EIP1559_TX_TYPE_ID, EIP2930_TX_TYPE_ID, EIP7702_TX_TYPE_ID, LEGACY_TX_TYPE_ID},
    eip2930::AccessList,
};
use alloy_primitives::Address;
use revm::context::TxEnv;
use seismic_alloy_consensus::{SeismicTxEnvelope, SEISMIC_TX_TYPE_ID};
use seismic_revm::{transaction::abstraction::RngMode, SeismicTransaction};
/// Trait marking types that can be converted into a transaction environment.
pub trait IntoTxEnv<TxEnv> {
    /// Converts `self` into [`TxEnv`].
    fn into_tx_env(self) -> TxEnv;
}

impl IntoTxEnv<Self> for TxEnv {
    fn into_tx_env(self) -> Self {
        self
    }
}

#[cfg(feature = "op")]
impl<T: revm::context::Transaction> IntoTxEnv<Self> for op_revm::OpTransaction<T> {
    fn into_tx_env(self) -> Self {
        self
    }
}

impl<T: revm::context::Transaction> IntoTxEnv<Self> for seismic_revm::SeismicTransaction<T> {
    fn into_tx_env(self) -> Self {
        self
    }
}

/// Helper user-facing trait to allow implementing [`IntoTxEnv`] on instances of [`Recovered`].
pub trait FromRecoveredTx<Tx> {
    /// Builds a `TxEnv` from a transaction and a sender address.
    fn from_recovered_tx(tx: &Tx, sender: Address) -> Self;
}

impl<TxEnv, T> FromRecoveredTx<&T> for TxEnv
where
    TxEnv: FromRecoveredTx<T>,
{
    fn from_recovered_tx(tx: &&T, sender: Address) -> Self {
        TxEnv::from_recovered_tx(tx, sender)
    }
}

impl<T, TxEnv: FromRecoveredTx<T>> IntoTxEnv<TxEnv> for Recovered<T> {
    fn into_tx_env(self) -> TxEnv {
        IntoTxEnv::into_tx_env(&self)
    }
}

impl<T, TxEnv: FromRecoveredTx<T>> IntoTxEnv<TxEnv> for &Recovered<T> {
    fn into_tx_env(self) -> TxEnv {
        TxEnv::from_recovered_tx(self.inner(), self.signer())
    }
}

impl FromRecoveredTx<SeismicTxEnvelope> for SeismicTransaction<TxEnv> {
    fn from_recovered_tx(tx: &SeismicTxEnvelope, sender: Address) -> Self {
        let base = match tx {
            SeismicTxEnvelope::Legacy(tx) => TxEnv {
                tx_type: LEGACY_TX_TYPE_ID,
                caller: sender,
                gas_limit: tx.tx().gas_limit,
                gas_price: tx.tx().gas_price,
                kind: tx.tx().kind(),
                value: tx.tx().value.into(),
                data: tx.tx().input.clone(),
                nonce: tx.tx().nonce,
                chain_id: tx.tx().chain_id,
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            SeismicTxEnvelope::Eip2930(tx) => TxEnv {
                tx_type: EIP2930_TX_TYPE_ID,
                caller: sender,
                gas_limit: tx.tx().gas_limit,
                gas_price: tx.tx().gas_price,
                kind: tx.tx().kind(),
                value: tx.tx().value.into(),
                data: tx.tx().input.clone(),
                nonce: tx.tx().nonce,
                chain_id: tx.tx().chain_id(),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            SeismicTxEnvelope::Eip1559(tx) => TxEnv {
                tx_type: EIP1559_TX_TYPE_ID,
                caller: sender,
                gas_limit: tx.tx().gas_limit,
                gas_price: tx.tx().gas_price().unwrap_or_default(),
                kind: tx.tx().kind(),
                value: tx.tx().value.into(),
                data: tx.tx().input.clone(),
                nonce: tx.tx().nonce,
                chain_id: tx.tx().chain_id(),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            SeismicTxEnvelope::Eip7702(tx) => TxEnv {
                tx_type: EIP7702_TX_TYPE_ID,
                caller: sender,
                gas_limit: tx.tx().gas_limit,
                gas_price: tx.tx().gas_price().unwrap_or_default(),
                kind: tx.tx().kind(),
                value: tx.tx().value.into(),
                data: tx.tx().input.clone(),
                nonce: tx.tx().nonce,
                chain_id: tx.tx().chain_id(),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            SeismicTxEnvelope::Seismic(tx) => TxEnv {
                tx_type: SEISMIC_TX_TYPE_ID,
                caller: sender,
                gas_limit: tx.tx().gas_limit,
                gas_price: tx.tx().gas_price().unwrap_or_default(),
                kind: tx.tx().kind(),
                value: tx.tx().value.into(),
                data: tx.tx().input.clone(),
                nonce: tx.tx().nonce,
                chain_id: tx.tx().chain_id(),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
        };
        SeismicTransaction { base, tx_hash: tx.tx_hash().clone(), rng_mode: RngMode::Execution }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MyTxEnv;
    struct MyTransaction;

    impl IntoTxEnv<Self> for MyTxEnv {
        fn into_tx_env(self) -> Self {
            self
        }
    }

    impl FromRecoveredTx<MyTransaction> for MyTxEnv {
        fn from_recovered_tx(_tx: &MyTransaction, _sender: Address) -> Self {
            Self
        }
    }

    const fn assert_env<T: IntoTxEnv<MyTxEnv>>() {}

    #[test]
    const fn test_into_tx_env() {
        assert_env::<MyTxEnv>();
        assert_env::<&Recovered<MyTransaction>>();
        assert_env::<&Recovered<&MyTransaction>>();
    }
}
