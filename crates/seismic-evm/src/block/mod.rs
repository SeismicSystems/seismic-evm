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
use alloy_evm::{
    block::{CommitChanges, ExecutableTx, InternalBlockExecutionError},
    FromTxWithEncoded,
};
use revm::context::result::ExecutionResult;
use seismic_alloy_consensus::InputDecryptionElements;
use seismic_enclave::{client::rpc::SyncEnclaveApiClient, rpc::SyncEnclaveApiClientBuilder};

type SeismicBlockExecutionCtx<'a> = EthBlockExecutionCtx<'a>;

/// Block executor for Seismic.
/// Wraps a [`EthBlockExecutor`] and decrypts the transaction input before executing
///
/// Note that only execute endpoints (e.g. eth_sendRawTransaction) will route through
/// the block executor, not simulate endpoints (e.g. eth_call, eth_estimateGas).
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
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction>
                + FromTxWithEncoded<R::Transaction>
                + ExecutableTx<Self>
                + InputDecryptionElements,
    >,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements,
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

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // seismic upstream merge: need to figure out how I can decrypt
        todo!("SeismicBlockExecutor::execute_transaction_with_commit_condition unimplimented in seismic-evm");

        // let mut tx = tx.into_tx_env();
        // let inner_ptr = tx.inner_mut();
        // let plaintext_copy = inner_ptr
        //     .plaintext_copy(&self.enclave_client)
        //     .map_err(|e| InternalBlockExecutionError::Other(Box::new(e)))?;
        // *inner_ptr = &plaintext_copy;

        // self.inner.execute_transaction_with_commit_condition(tx, f)
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        let mut tx: <E as Evm>::Tx = tx.into_tx_env();
        let plaintext_copy = tx
            .plaintext_copy(&self.enclave_client)
            .map_err(|e| InternalBlockExecutionError::Other(Box::new(e)))?;
        let copy: <E as Evm>::Tx = plaintext_copy.clone();

        // ExecutableTx<EthBlockExecutor<'_, E, Spec, R>>

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

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

/// Seismic block executor factory.
#[derive(Debug, Clone, Default, Copy)]
pub struct SeismicBlockExecutorFactory<
    CB,
    R = SeismicAlloyReceiptBuilder,
    Spec = SeismicChainHardforks,
    EvmFactory = SeismicEvmFactory<CB>,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
    /// Enclave client.
    client_builder: CB,
}

impl<CB, R, Spec, EvmFactory> SeismicBlockExecutorFactory<CB, R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`SeismicReceiptBuilder`].
    pub const fn new(
        receipt_builder: R,
        spec: Spec,
        evm_factory: EvmFactory,
        client_builder: CB,
    ) -> Self {
        Self { receipt_builder, spec, evm_factory, client_builder }
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

    /// Exposes the enclave client builder.
    pub const fn client_builder(&self) -> &CB {
        &self.client_builder
    }
}

impl<CB, R, Spec, EvmF> BlockExecutorFactory for SeismicBlockExecutorFactory<CB, R, Spec, EvmF>
where
    R: ReceiptBuilder<
        Transaction: Transaction + Encodable2718 + InputDecryptionElements + Clone,
        Receipt: TxReceipt<Log = Log>,
    >,
    Spec: SeismicHardforks + EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>>,
    CB: SyncEnclaveApiClientBuilder + Clone,
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
        let enclave_client = self.client_builder.clone().build();
        SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder, enclave_client)
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
    use seismic_alloy_consensus::{TxSeismic, TxSeismicElements};
    use seismic_enclave::{
        nonce::Nonce, rand, tx_io::IoEncryptionRequest, MockEnclaveClientBuilder, PublicKey,
        Secp256k1, SecretKey,
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
        executor_factory: SeismicBlockExecutorFactory<MockEnclaveClientBuilder>,
        ctx: SeismicBlockExecutionCtx<'a>,
        enclave_builder: MockEnclaveClientBuilder,
        encryption_pubkey: PublicKey,
        encryption_nonce: Nonce,
        evm_factory: SeismicEvmFactory<MockEnclaveClientBuilder>,
    }

    fn setup_test<'a>(state: &mut State<InMemoryDB>) -> SetupTest<'a> {
        let rng = &mut rand::thread_rng();
        let signing_key = SigningKey::random(rng);
        let pubkey = signing_key.verifying_key();
        let signer = public_key_to_address(*pubkey);

        let sk = SecretKey::new(rng);
        let secp = Secp256k1::new();
        let encryption_pubkey = PublicKey::from_secret_key(&secp, &sk);

        let enclave_builder = MockEnclaveClientBuilder::new();
        let evm_factory = SeismicEvmFactory::new(enclave_builder.clone());

        state.increment_balances(vec![(signer, 1000000000000000000)]).unwrap();
        let executor_factory = SeismicBlockExecutorFactory::new(
            SeismicAlloyReceiptBuilder::default(),
            SeismicChainHardforks::seismic_mainnet(),
            evm_factory.clone(),
            enclave_builder.clone(),
        );

        let ctx = SeismicBlockExecutionCtx {
            withdrawals: None,
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &[],
        };
        SetupTest {
            encryption_pubkey,
            signer,
            signing_key,
            executor_factory,
            ctx,
            enclave_builder,
            encryption_nonce: Nonce::new_rand(),
            evm_factory,
        }
    }

    fn get_tx_envelope<'a>(setup: &SetupTest<'a>, tx_seismic: TxSeismic) -> SeismicTxEnvelope {
        let sig = sign_seismic_tx(&tx_seismic, &setup.signing_key);
        let tx_signed = SignableTransaction::into_signed(tx_seismic, sig);
        let tx_envelope = SeismicTxEnvelope::Seismic(tx_signed);
        return tx_envelope;
    }

    fn sample_seismic_tx<'a>(setup: &SetupTest<'a>, plaintext: &str) -> TxSeismic {
        let ciphertext = setup
            .enclave_builder
            .clone()
            .build()
            .encrypt(IoEncryptionRequest {
                key: setup.encryption_pubkey,
                data: plaintext.as_bytes().to_vec(),
                nonce: setup.encryption_nonce.clone(),
            })
            .unwrap()
            .encrypted_data;
        TxSeismic {
            chain_id: 5124,
            nonce: 0,
            gas_price: 1000000000,
            gas_limit: 1000000,
            to: TxKind::Call(Address::ZERO),
            value: U256::from(0),
            input: Bytes::from(ciphertext),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: setup.encryption_pubkey,
                encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
                message_version: 0,
            },
        }
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

    // Expected behavior for now is panic as MockClient panics on bad encryption/decryption
    // This test case may need to be updated if the MockClient is changed to return
    #[test]
    #[should_panic]
    fn test_incorrect_encryption() {
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

        let result = executor.execute_transaction(recovered);
        assert!(result.is_err(), "expected transaction to fail, but got: {:?}", result);
    }
}
