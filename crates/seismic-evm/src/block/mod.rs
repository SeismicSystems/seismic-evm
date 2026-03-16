//! Block executor for Seismic.

use crate::{
    hardfork::{SeismicChainHardforks, SeismicHardforks},
    SeismicEvmFactory,
};
use alloy_consensus::{Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, OnStateHook,
    },
    eth::{
        receipt_builder::ReceiptBuilder, spec::EthExecutorSpec, EthBlockExecutionCtx,
        EthBlockExecutor,
    },
    Database, Evm, EvmFactory, FromRecoveredTx,
};
use alloy_primitives::Log;
pub use receipt_builder::SeismicAlloyReceiptBuilder;
use revm::{database::State, Inspector};
pub mod receipt_builder;
use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    block::{CommitChanges, ExecutableTx, InternalBlockExecutionError},
    FromTxWithEncoded, RecoveredTx, ToTxEnv,
};
use alloy_primitives::U256;
use revm::{
    context::{result::ExecutionResult, TxEnv},
    context_interface::ContextTr,
};
use seismic_alloy_consensus::InputDecryptionElements;
use seismic_revm::{transaction::abstraction::SeismicTransaction, SeismicChain};

/// Trait for accessing the SeismicChain from within a generic EVM context.
/// Implemented by [`crate::SeismicEvm`] to allow the block executor to set
/// RNG domain data (parent_block_hash, tx_hash_accumulator).
pub trait SeismicChainAccess {
    /// Returns a mutable reference to the [`SeismicChain`].
    fn seismic_chain_mut(&mut self) -> &mut SeismicChain;
}

impl<DB: Database, I, P> SeismicChainAccess for crate::SeismicEvm<DB, I, P> {
    fn seismic_chain_mut(&mut self) -> &mut SeismicChain {
        self.ctx_mut().chain_mut()
    }
}

type SeismicBlockExecutionCtx<'a> = EthBlockExecutionCtx<'a>;

/// Block executor for Seismic.
/// Wraps a [`EthBlockExecutor`] and decrypts the transaction input before executing
///
/// Note that only execute endpoints (e.g. eth_sendRawTransaction) will route through
/// the block executor, not simulate endpoints (e.g. eth_call, eth_estimateGas).
#[derive(Debug)]
pub struct SeismicBlockExecutor<'a, Evm, Spec, R>
where
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
{
    inner: EthBlockExecutor<'a, Evm, Spec, R>,
    purpose_keys: &'static seismic_enclave::GetPurposeKeysResponse,
}

impl<'a, E, Spec, R> SeismicBlockExecutor<'a, E, Spec, R>
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
        purpose_keys: &'static seismic_enclave::GetPurposeKeysResponse,
    ) -> Self {
        Self { inner: EthBlockExecutor::new(evm, ctx, spec, receipt_builder), purpose_keys }
    }
}

/// Wrapper that marks a transaction as having failed calldata decryption.
///
/// When converted to `SeismicTransaction<TxEnv>` via [`ToTxEnv`], the resulting
/// transaction has `decryption_failed = true`, causing the handler to skip bytecode
/// execution and charge only intrinsic gas.
struct DecryptionFailed<T>(T);

impl<T> ToTxEnv<SeismicTransaction<TxEnv>> for DecryptionFailed<T>
where
    T: ToTxEnv<SeismicTransaction<TxEnv>>,
{
    fn to_tx_env(&self) -> SeismicTransaction<TxEnv> {
        let mut tx = self.0.to_tx_env();
        tx.decryption_failed = true;
        // Zero value so revm's validation doesn't require the sender to cover
        // a transfer amount that will never happen (execution is skipped).
        tx.base.value = U256::ZERO;
        tx
    }
}

impl<T, Tx> RecoveredTx<Tx> for DecryptionFailed<T>
where
    T: RecoveredTx<Tx>,
{
    fn tx(&self) -> &Tx {
        self.0.tx()
    }

    fn signer(&self) -> &alloy_primitives::Address {
        self.0.signer()
    }
}

impl<'db, DB, E, Spec, R> BlockExecutor for SeismicBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = SeismicTransaction<TxEnv>> + SeismicChainAccess,
    SeismicTransaction<TxEnv>: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements + Clone,
        Receipt: TxReceipt<Log = Log>,
    >,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        let parent_hash = self.inner.ctx.parent_hash;
        self.evm_mut().seismic_chain_mut().set_parent_block_hash(parent_hash);
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        let receipt_tx: &<R as ReceiptBuilder>::Transaction = RecoveredTx::tx(&tx);
        let current_block: u64 = self.evm().block().number.saturating_to();
        receipt_tx
            .validate_block(current_block, &[self.inner.ctx.parent_hash])
            .map_err(InternalBlockExecutionError::SeismicValidationFailed)?;

        let tx_hash = receipt_tx.trie_hash();

        let signer = RecoveredTx::signer(&tx);
        let result = match receipt_tx.plaintext_copy(&self.purpose_keys.tx_io_sk, *signer) {
            Ok(plaintext_base) => {
                let recovered = Recovered::new_unchecked(plaintext_base, *signer);
                self.inner.execute_transaction_with_commit_condition(&recovered, f)?
            }
            Err(_) => {
                // Decryption failed: wrap in DecryptionFailed so the handler
                // skips bytecode execution and charges intrinsic gas (including
                // calldata cost). revm handles all gas accounting (sender debit,
                // coinbase credit, gas refund) natively.
                let recovered = Recovered::new_unchecked(receipt_tx.clone(), *signer);
                self.inner
                    .execute_transaction_with_commit_condition(DecryptionFailed(&recovered), f)?
            }
        };

        // Advance the tx hash accumulator only if the transaction was committed.
        if result.is_some() {
            self.evm_mut().seismic_chain_mut().advance_tx_accumulator(&tx_hash);
        }
        Ok(result)
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        let receipt_tx: &<R as ReceiptBuilder>::Transaction = RecoveredTx::tx(&tx);
        let current_block: u64 = self.evm().block().number.saturating_to();
        receipt_tx
            .validate_block(current_block, &[self.inner.ctx.parent_hash])
            .map_err(InternalBlockExecutionError::SeismicValidationFailed)?;

        let tx_hash = receipt_tx.trie_hash();

        let signer = RecoveredTx::signer(&tx);
        let result = match receipt_tx.plaintext_copy(&self.purpose_keys.tx_io_sk, *signer) {
            Ok(plaintext_base) => {
                let recovered = Recovered::new_unchecked(plaintext_base, *signer);
                self.inner.execute_transaction_with_result_closure(&recovered, f)?
            }
            Err(_) => {
                let recovered = Recovered::new_unchecked(receipt_tx.clone(), *signer);
                self.inner
                    .execute_transaction_with_result_closure(DecryptionFailed(&recovered), f)?
            }
        };

        // Always advance accumulator (this path always commits).
        self.evm_mut().seismic_chain_mut().advance_tx_accumulator(&tx_hash);
        Ok(result)
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

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

/// Seismic block executor factory.
#[derive(Debug, Clone)]
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
    /// Purpose keys for decryption.
    pub purpose_keys: &'static seismic_enclave::GetPurposeKeysResponse,
}

impl<R, Spec, EvmFactory> SeismicBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`SeismicReceiptBuilder`].
    pub const fn new(
        receipt_builder: R,
        spec: Spec,
        evm_factory: EvmFactory,
        purpose_keys: &'static seismic_enclave::GetPurposeKeysResponse,
    ) -> Self {
        Self { receipt_builder, spec, evm_factory, purpose_keys }
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

impl<R, Spec> BlockExecutorFactory for SeismicBlockExecutorFactory<R, Spec, SeismicEvmFactory>
where
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements + Clone,
        Receipt: TxReceipt<Log = Log>,
    >,
    Spec: SeismicHardforks + EthExecutorSpec,
    SeismicTransaction<TxEnv>: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    Self: 'static,
{
    type EvmFactory = SeismicEvmFactory;
    type ExecutionCtx<'a> = SeismicBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <SeismicEvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<<SeismicEvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder, self.purpose_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::SignableTransaction;
    use alloy_evm::EvmEnv;
    use alloy_primitives::{aliases::U96, keccak256, Bytes, Signature, TxKind, B256, U256};
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use revm::{
        context::{BlockEnv, CfgEnv},
        database::{InMemoryDB, StateBuilder},
    };
    use seismic_alloy_consensus::{
        TxLegacyFields, TxSeismic, TxSeismicElements, TxSeismicMetadata,
    };
    use seismic_enclave::{
        get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
        get_unsecure_sample_secp256k1_sk,
        secp256k1::{rand, PublicKey, Secp256k1, SecretKey},
        GetPurposeKeysResponse, Nonce,
    };
    use seismic_revm::SeismicSpecId;

    use alloy_consensus::transaction::Recovered;
    use alloy_primitives::Address;
    use seismic_alloy_consensus::SeismicTxEnvelope;

    fn sign_seismic_tx(tx: &TxSeismic, signing_key: &SigningKey) -> Signature {
        let _signature = signing_key
            .clone()
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .expect("Failed to sign");

        let recoverid = _signature.1;
        let _signature = _signature.0;

        let signature = Signature::new(
            U256::from_be_slice(_signature.r().to_bytes().as_slice()),
            U256::from_be_slice(_signature.s().to_bytes().as_slice()),
            recoverid.is_y_odd(),
        );

        signature
    }

    fn public_key_to_address(public: VerifyingKey) -> Address {
        let hash = keccak256(&public.to_encoded_point(/* compress = */ false).as_bytes()[1..]);
        Address::from_slice(&hash[12..])
    }

    #[derive(Clone)]
    struct SetupTest<'a> {
        signer: Address,
        signing_key: SigningKey,
        executor_factory: SeismicBlockExecutorFactory,
        ctx: SeismicBlockExecutionCtx<'a>,
        purpose_keys: &'static seismic_enclave::GetPurposeKeysResponse,
        encryption_pubkey: PublicKey,
        encryption_sk: SecretKey,
        encryption_nonce: Nonce,
        evm_factory: SeismicEvmFactory,
    }

    fn setup_test<'a>(state: &mut State<InMemoryDB>) -> SetupTest<'a> {
        let rng = &mut rand::thread_rng();
        let signing_key = SigningKey::random(rng);
        let pubkey = signing_key.verifying_key();
        let signer = public_key_to_address(*pubkey);

        let encryption_sk = SecretKey::new(rng);
        let secp = Secp256k1::new();
        let encryption_pubkey = PublicKey::from_secret_key(&secp, &encryption_sk);

        // Fetch purpose keys for testing and leak to get 'static lifetime
        let mock_keys = Box::leak(Box::new(get_mock_keys()));
        let evm_factory = SeismicEvmFactory::new_with_purpose_keys(mock_keys);

        state.increment_balances(vec![(signer, 1000000000000000000)]).unwrap();
        let executor_factory = SeismicBlockExecutorFactory::new(
            SeismicAlloyReceiptBuilder::default(),
            SeismicChainHardforks::seismic_mainnet(),
            evm_factory.clone(),
            mock_keys,
        );

        let ctx = SeismicBlockExecutionCtx {
            withdrawals: None,
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &[],
        };
        SetupTest {
            encryption_pubkey,
            encryption_sk,
            signer,
            signing_key,
            executor_factory,
            ctx,
            purpose_keys: mock_keys,
            encryption_nonce: Nonce::new_rand(),
            evm_factory,
        }
    }

    fn get_mock_keys() -> GetPurposeKeysResponse {
        GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        }
    }

    fn get_tx_envelope<'a>(setup: &SetupTest<'a>, tx_seismic: TxSeismic) -> SeismicTxEnvelope {
        let sig = sign_seismic_tx(&tx_seismic, &setup.signing_key);
        let tx_signed = SignableTransaction::into_signed(tx_seismic, sig);
        let tx_envelope = SeismicTxEnvelope::Seismic(tx_signed);
        return tx_envelope;
    }

    fn sample_seismic_tx_with_elements<'a>(
        setup: &SetupTest<'a>,
        plaintext: &str,
        seismic_elements: TxSeismicElements,
    ) -> TxSeismic {
        let pt_bytes = Bytes::from(plaintext.as_bytes().to_vec());

        let tx_metadata = TxSeismicMetadata {
            sender: setup.signer,
            legacy_fields: TxLegacyFields {
                chain_id: 5124,
                nonce: 0,
                to: TxKind::Call(Address::ZERO),
                value: U256::from(0),
            },
            seismic_elements,
        };

        let ciphertext = tx_metadata
            .client_encrypt(&pt_bytes, &setup.purpose_keys.tx_io_pk, &setup.encryption_sk)
            .unwrap();

        TxSeismic {
            chain_id: tx_metadata.legacy_fields.chain_id,
            nonce: tx_metadata.legacy_fields.nonce,
            gas_price: 1000000000,
            gas_limit: 1000000,
            to: tx_metadata.legacy_fields.to,
            value: tx_metadata.legacy_fields.value,
            input: ciphertext,
            seismic_elements: tx_metadata.seismic_elements,
            authorization_list: vec![],
        }
    }

    fn sample_seismic_tx<'a>(setup: &SetupTest<'a>, plaintext: &str) -> TxSeismic {
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            // Must match setup_test's parent_hash (B256::ZERO)
            recent_block_hash: B256::ZERO,
            expires_at_block: 1000000,
            signed_read: false,
        };
        sample_seismic_tx_with_elements(setup, plaintext, seismic_elements)
    }

    #[test]
    fn test_transaction_decryption_in_executor() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let tx_seismic = sample_seismic_tx(&setup, plaintext);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);
        executor.execute_transaction(recovered).unwrap();
    }

    /// Decryption failure is now handled as a metered transaction failure:
    /// the sender is charged intrinsic gas and a failed receipt is emitted.
    #[test]
    fn test_incorrect_encryption_charges_gas() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let mut tx_seismic = sample_seismic_tx(&setup, plaintext);

        let rng = &mut rand::thread_rng();
        let wrong_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::new(rng));
        tx_seismic.seismic_elements.encryption_pubkey = wrong_pubkey;
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let gas_used = executor
            .execute_transaction(recovered)
            .expect("decryption failure should be handled gracefully");

        // Should charge intrinsic gas (21000 base + per-byte calldata cost)
        assert!(gas_used > 21_000, "should charge base gas plus calldata gas, got: {gas_used}");
    }

    /// Decryption failure produces a receipt with status=0 and is properly
    /// accounted for in the block result.
    #[test]
    fn test_decrypt_failure_emits_failed_receipt() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let mut tx_seismic = sample_seismic_tx(&setup, plaintext);
        let rng = &mut rand::thread_rng();
        let wrong_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::new(rng));
        tx_seismic.seismic_elements.encryption_pubkey = wrong_pubkey;

        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);
        executor.execute_transaction(recovered).expect("should handle decryption failure");

        let (_, block_result) = executor.finish().expect("finish should succeed");
        assert_eq!(block_result.receipts.len(), 1, "should produce exactly one receipt");
        assert!(block_result.gas_used > 0, "block gas_used should reflect charged gas");
        assert!(!block_result.receipts[0].status(), "receipt should have failed status (status=0)");
    }

    /// Block execution continues after a decryption failure — subsequent valid
    /// transactions still execute normally.
    #[test]
    fn test_block_continues_after_decrypt_failure() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        // First: a bad decryption tx
        let mut bad_tx = sample_seismic_tx(&setup, "bad-decrypt");
        let rng = &mut rand::thread_rng();
        let wrong_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::new(rng));
        bad_tx.seismic_elements.encryption_pubkey = wrong_pubkey;
        let bad_envelope = get_tx_envelope(&setup, bad_tx);
        let bad_recovered = Recovered::new_unchecked(&bad_envelope, setup.signer);
        executor.execute_transaction(bad_recovered).expect("bad decrypt should be handled");

        // Second: a valid tx (nonce=1 because the failed tx consumed nonce=0)
        let mut good_tx = sample_seismic_tx(&setup, "valid-tx");
        good_tx.nonce = 1;
        let good_envelope = get_tx_envelope(&setup, good_tx);
        let good_recovered = Recovered::new_unchecked(&good_envelope, setup.signer);
        executor.execute_transaction(good_recovered).expect("valid tx should succeed");

        let (_, block_result) = executor.finish().expect("finish should succeed");
        assert_eq!(block_result.receipts.len(), 2, "should have receipts for both transactions");
        assert!(
            block_result.gas_used > 21_000,
            "total gas should exceed intrinsic gas for the failed tx"
        );
    }

    #[test]
    fn test_expired_tx_rejected() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        // Set block number to 100 so the tx with expires_at_block=50 is expired
        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(100);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            recent_block_hash: B256::ZERO,
            expires_at_block: 50,
            signed_read: false,
        };
        let tx_seismic = sample_seismic_tx_with_elements(&setup, plaintext, seismic_elements);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let result = executor.execute_transaction(recovered);
        assert!(result.is_err(), "expired transaction should be rejected, but it was accepted");
    }

    #[test]
    fn test_tx_at_exact_expiry_block_accepted() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        // Set block number exactly equal to expires_at_block (should still be valid)
        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(100);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            recent_block_hash: B256::ZERO,
            expires_at_block: 100,
            signed_read: false,
        };
        let tx_seismic = sample_seismic_tx_with_elements(&setup, plaintext, seismic_elements);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let result = executor.execute_transaction(recovered);
        assert!(
            result.is_ok(),
            "transaction at exact expiry block should be accepted, got: {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_recent_block_hash_rejected() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            recent_block_hash: B256::from_slice(&[0xAB; 32]), // Doesn't match parent_hash
            expires_at_block: 1000000,
            signed_read: false,
        };
        let tx_seismic = sample_seismic_tx_with_elements(&setup, plaintext, seismic_elements);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let result = executor.execute_transaction(recovered);
        assert!(result.is_err(), "transaction with invalid recent_block_hash should be rejected");
    }

    #[test]
    fn test_tx_one_block_past_expiry_rejected() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();

        let setup = setup_test(&mut state);

        // Set block number to one past expires_at_block
        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(101);

        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());

        let plaintext = "hello world";
        let seismic_elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            recent_block_hash: B256::ZERO,
            expires_at_block: 100,
            signed_read: false,
        };
        let tx_seismic = sample_seismic_tx_with_elements(&setup, plaintext, seismic_elements);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let result = executor.execute_transaction(recovered);
        assert!(
            result.is_err(),
            "transaction one block past expiry should be rejected, but it was accepted"
        );
    }
}
