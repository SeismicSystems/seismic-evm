//! Block executor for Seismic.

use crate::{
    hardfork::{SeismicChainHardforks, SeismicHardforks},
    BlockKeySelection, PurposeKeyring, SeismicEvmFactory,
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
use std::sync::Arc;
pub mod receipt_builder;
use alloy_consensus::transaction::Recovered;
use alloy_evm::{
    block::{BlockValidationError, CommitChanges, ExecutableTx},
    FromTxWithEncoded, RecoveredTx, ToTxEnv,
};
use alloy_primitives::{B256, U256};
use revm::{
    context::{result::ExecutionResult, TxEnv},
    context_interface::ContextTr,
};
use seismic_alloy_consensus::{InputDecryptionElements, SeismicValidationError};
use seismic_revm::{transaction::abstraction::SeismicTransaction, SeismicChain};

/// Trait for accessing the SeismicChain from within a generic EVM context.
/// Implemented by [`crate::SeismicEvm`] to allow the block executor to set
/// RNG domain data (parent_block_hash, tx_hash_accumulator).
pub trait SeismicChainAccess {
    /// Returns a mutable reference to the [`SeismicChain`].
    fn seismic_chain_mut(&mut self) -> &mut SeismicChain;

    /// Resolve and freeze keys from the EVM's parent-state database.
    fn initialize_block_keys(&mut self) -> Result<BlockKeySelection, BlockExecutionError>;
}

impl<DB: Database, I, P> SeismicChainAccess for crate::SeismicEvm<DB, I, P> {
    fn seismic_chain_mut(&mut self) -> &mut SeismicChain {
        self.ctx_mut().chain_mut()
    }

    fn initialize_block_keys(&mut self) -> Result<BlockKeySelection, BlockExecutionError> {
        self.initialize_keys().cloned().map_err(crate::KeySelectionError::into_block_error)
    }
}

/// Maximum number of blocks to look back for `recent_block_hash` validation.
/// Must match `SEISMIC_TX_RECENT_BLOCK_LOOKBACK` in seismic-reth txpool.
const SEISMIC_TX_RECENT_BLOCK_LOOKBACK: u64 = 100;

/// Trait for looking up block hashes from the EVM's database.
/// Implemented by [`crate::SeismicEvm`] to allow the block executor to
/// validate `recent_block_hash` against a window of recent blocks.
pub trait BlockHashReader {
    /// Error returned by the underlying database.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Returns the block hash for the given block number, propagating DB errors.
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error>;
}

impl<DB: Database, I, P> BlockHashReader for crate::SeismicEvm<DB, I, P> {
    type Error = DB::Error;

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        revm::Database::block_hash(self.ctx_mut().db_mut(), number)
    }
}

type SeismicBlockExecutionCtx<'a> = EthBlockExecutionCtx<'a>;

/// Block executor for Seismic.
/// Wraps a [`EthBlockExecutor`] and decrypts the transaction input before executing
///
/// Ordinary block executors validate freshness and decrypt encrypted transactions.
/// Request-local RPC simulation factories may opt in to already-authenticated plaintext
/// signed reads; that mode must never be enabled for payload building or received blocks.
#[derive(Debug)]
pub struct SeismicBlockExecutor<'a, Evm, Spec, R>
where
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
{
    inner: EthBlockExecutor<'a, Evm, Spec, R>,
    /// Owned selection; never re-read shared metadata while executing transactions.
    selected: Option<BlockKeySelection>,
    /// Only request-local RPC factories enable already-authenticated plaintext signed reads.
    plaintext_signed_reads: bool,
}

impl<'a, E, Spec, R> SeismicBlockExecutor<'a, E, Spec, R>
where
    E: Evm,
    R: ReceiptBuilder,
    R::Receipt: std::fmt::Debug,
{
    /// Creates a new [`SeismicBlockExecutor`].
    pub fn new(evm: E, ctx: SeismicBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self
    where
        Spec: Clone,
    {
        Self {
            inner: EthBlockExecutor::new(evm, ctx, spec, receipt_builder),
            selected: None,
            plaintext_signed_reads: false,
        }
    }

    fn selected_keys(&self) -> Result<&BlockKeySelection, BlockExecutionError> {
        self.selected
            .as_ref()
            .ok_or_else(|| BlockExecutionError::msg("block purpose-key selection is uninitialized"))
    }
}

/// Wrapper that marks a transaction as having failed calldata decryption.
///
/// When converted to `SeismicTransaction<TxEnv>` via [`ToTxEnv`], the resulting
/// transaction has `decryption_failed = true`, causing the handler to skip bytecode
/// execution. Fee settlement still applies intrinsic gas and the applicable calldata gas floor.
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

#[derive(Debug, thiserror::Error)]
#[error(
    "block hash lookup for block {number} failed while validating transaction {tx_hash}: {source}"
)]
struct BlockHashLookupError<E> {
    number: u64,
    tx_hash: B256,
    #[source]
    source: E,
}

#[derive(Debug)]
enum FreshnessCheckError<E> {
    Validation(SeismicValidationError),
    Database { number: u64, source: E },
}

impl<E: core::error::Error + Send + Sync + 'static> FreshnessCheckError<E> {
    fn into_block_error(self, hash: B256) -> BlockExecutionError {
        match self {
            Self::Database { number, source } => {
                BlockExecutionError::other(BlockHashLookupError { number, tx_hash: hash, source })
            }
            Self::Validation(error) => {
                BlockValidationError::InvalidTx { hash, error: Box::new(error) }.into()
            }
        }
    }
}

fn validate_tx_decryption_elements<
    R: Transaction + Encodable2718 + InputDecryptionElements + Clone,
    H: BlockHashReader,
>(
    tx: &R,
    current_block: u64,
    parent_hash: B256,
    block_hash_reader: &mut H,
) -> Result<(), FreshnessCheckError<H::Error>> {
    let elements = match tx.get_decryption_elements() {
        Ok(elements) => elements,
        Err(_) => return Ok(()), // No decryption elements; nothing to validate
    };

    if current_block > elements.expires_at_block {
        return Err(FreshnessCheckError::Validation(SeismicValidationError::TransactionExpired {
            current_block,
            expires_at_block: elements.expires_at_block,
        }));
    }

    // Fast path: check parent hash directly
    if elements.recent_block_hash == parent_hash {
        return Ok(());
    }

    // Walk backwards through the lookback window
    let oldest = current_block.saturating_sub(SEISMIC_TX_RECENT_BLOCK_LOOKBACK);
    for n in (oldest..current_block.saturating_sub(1)).rev() {
        let hash = block_hash_reader
            .block_hash(n)
            .map_err(|source| FreshnessCheckError::Database { number: n, source })?;
        if hash == elements.recent_block_hash {
            return Ok(());
        }
    }

    Err(FreshnessCheckError::Validation(SeismicValidationError::InvalidRecentBlockHash {
        provided_hash: elements.recent_block_hash,
    }))
}

impl<'db, DB, E, Spec, R> BlockExecutor for SeismicBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<DB = &'db mut State<DB>, Tx = SeismicTransaction<TxEnv>>
        + SeismicChainAccess
        + BlockHashReader,
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
        // Resolve before any pre-execution state changes. The EVM also freezes
        // this selection so system calls and raw transaction execution agree.
        self.selected = None;
        let selected = self.evm_mut().initialize_block_keys()?;
        self.evm_mut().seismic_chain_mut().set_rng_key(selected.keys.rng_ikm);
        let parent_hash = self.inner.ctx.parent_hash;
        self.evm_mut().seismic_chain_mut().set_parent_block_hash(parent_hash);
        self.inner.apply_pre_execution_changes()?;
        self.selected = Some(selected);
        Ok(())
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        let tx_io_sk = self.selected_keys()?.keys.tx_io.secret_key();
        let receipt_tx: &<R as ReceiptBuilder>::Transaction = RecoveredTx::tx(&tx);
        let current_block: u64 = self.evm().block().number.saturating_to();
        let parent_hash = self.inner.ctx.parent_hash;

        let tx_hash = receipt_tx.trie_hash();

        let result = if self.plaintext_signed_reads && tx.to_tx_env().signed_read {
            // The RPC ingress already authenticates, validates tip freshness, and decrypts
            // these call-only requests. Simulated block heights do not revalidate their
            // expiry and plaintext must not be decrypted a second time. This mode is
            // opt-in on a request-local factory, never inferred solely from a wire flag.
            self.inner.execute_transaction_with_commit_condition(tx, f)?
        } else {
            // Stale or expired transactions are invalid; DB failures are internal errors.
            validate_tx_decryption_elements(receipt_tx, current_block, parent_hash, self.evm_mut())
                .map_err(|error| error.into_block_error(tx_hash))?;

            let signer = RecoveredTx::signer(&tx);
            match receipt_tx.plaintext_copy(&tx_io_sk, *signer) {
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
                    self.inner.execute_transaction_with_commit_condition(
                        DecryptionFailed(&recovered),
                        f,
                    )?
                }
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
        // Keep decryption, simulation handling, and accumulator updates identical
        // across both entry points. The result-closure path always commits.
        self.execute_transaction_with_commit_condition(tx, |result| {
            f(result);
            CommitChanges::Yes
        })?
        .ok_or_else(|| BlockExecutionError::msg("committed transaction produced no gas result"))
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        self.selected_keys()?;
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
    /// Epoch-keyed purpose keys; executors select their block's epoch through it.
    pub keyring: Arc<PurposeKeyring>,
    /// Opt-in only for request-local simulations of authenticated plaintext signed reads.
    plaintext_signed_reads: bool,
}

impl<R, Spec, EvmFactory> SeismicBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`SeismicBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`ReceiptBuilder`].
    pub fn new(
        receipt_builder: R,
        spec: Spec,
        evm_factory: EvmFactory,
        keyring: Arc<PurposeKeyring>,
    ) -> Self {
        Self { receipt_builder, spec, evm_factory, keyring, plaintext_signed_reads: false }
    }

    /// Permit already-authenticated and decrypted signed reads in an RPC simulation.
    ///
    /// Enable only on a request-local factory whose ingress enforces signature,
    /// signed-read intent, freshness, and decryption. Ordinary encrypted transactions
    /// (including replay) still use the live decryption and validation path. Never
    /// enable this on the factory used for payload building or received blocks.
    pub const fn with_plaintext_signed_reads(mut self) -> Self {
        self.plaintext_signed_reads = true;
        self
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
        let mut executor = SeismicBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder);
        executor.plaintext_signed_reads = self.plaintext_signed_reads;
        executor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalRotationView, PurposeKeys, RotationEntry, RotationSchedule};
    use alloy_consensus::SignableTransaction;
    use alloy_evm::EvmEnv;
    use alloy_primitives::{
        aliases::U96, keccak256, Bytes, FlaggedStorage, Signature, TxKind, B256, U256,
    };
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use revm::{
        bytecode::Bytecode,
        context::{BlockEnv, CfgEnv},
        database::{InMemoryDB, StateBuilder},
        database_interface::DBErrorMarker,
        state::AccountInfo,
        Database as RevmDatabase,
    };
    use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
    use seismic_alloy_consensus::{
        TxLegacyFields, TxSeismic, TxSeismicElements, TxSeismicMetadata,
    };
    use seismic_crypto::Nonce;
    use seismic_revm::SeismicSpecId;

    use alloy_consensus::transaction::Recovered;
    use alloy_primitives::Address;
    use seismic_alloy_consensus::SeismicTxEnvelope;

    fn rotation_db() -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            crate::registry::KEY_ROTATION_REGISTRY,
            revm::state::AccountInfo::default(),
        );
        db.insert_account_storage(
            crate::registry::KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(crate::registry::ROTATIONS_LEN_SLOT.0),
            U256::from(1).into(),
        )
        .unwrap();
        db.insert_account_storage(
            crate::registry::KEY_ROTATION_REGISTRY,
            U256::from_be_bytes(crate::registry::rotation_entry_slot(0).0),
            U256::from_limbs([1, 100, 10, 0]).into(),
        )
        .unwrap();
        db
    }

    #[test]
    fn decryption_failure_changes_only_execution_value_and_failure_flag() {
        use seismic_alloy_consensus::GasPayment;
        for gas_payment in
            [GasPayment::Auto, GasPayment::Native, GasPayment::Token(Address::repeat_byte(0x77))]
        {
            let original = TxSeismic { value: U256::from(123), gas_payment, ..Default::default() };
            let signed =
                original.clone().into_signed(Signature::new(U256::from(1), U256::from(2), false));
            let envelope = SeismicTxEnvelope::from(signed);
            let hash = *envelope.tx_hash();
            let wrapper =
                DecryptionFailed(Recovered::new_unchecked(envelope, Address::repeat_byte(0x11)));
            let env = wrapper.to_tx_env();
            let mut expected: SeismicTransaction<TxEnv> = wrapper.0.to_tx_env();
            expected.decryption_failed = true;
            expected.base.value = U256::ZERO;
            assert_eq!(env, expected, "only execution value and the failure flag may change");
            assert!(env.decryption_failed);
            assert_eq!(env.base.value, U256::ZERO);
            assert_eq!(env.gas_payment, alloy_evm::tx::gas_payment_to_env(gas_payment));
            assert_eq!(env.tx_hash, hash);
            assert_eq!(*wrapper.0.inner().tx_hash(), hash);
            let SeismicTxEnvelope::Seismic(tx) = wrapper.0.inner() else {
                panic!("expected seismic transaction")
            };
            assert_eq!(
                tx.tx(),
                &original,
                "signed value, selector, and all metadata remain unchanged"
            );
        }
    }

    fn first_tx_accumulator(hash: B256) -> B256 {
        keccak256([B256::ZERO.as_slice(), hash.as_slice()].concat())
    }

    #[test]
    fn plaintext_signed_reads_require_request_local_opt_in() {
        for enabled in [false, true] {
            for use_result_closure in [false, true] {
                for inspected in [false, true] {
                    let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
                    let setup = setup_test(&mut state);
                    let mut cfg = CfgEnv::new_with_spec(SeismicSpecId::MERCURY);
                    cfg.chain_id = 5124;
                    let mut evm = setup.evm_factory.create_evm(
                        &mut state,
                        EvmEnv::new(
                            cfg,
                            BlockEnv { number: U256::from(100), ..Default::default() },
                        ),
                    );
                    evm.set_inspector_enabled(inspected);
                    let factory = if enabled {
                        setup.executor_factory.clone().with_plaintext_signed_reads()
                    } else {
                        setup.executor_factory.clone()
                    };
                    let mut executor = factory.create_executor(evm, setup.ctx.clone());
                    executor.apply_pre_execution_changes().unwrap();
                    // Trusted RPC ingress authenticated/decrypted at an earlier tip. A future
                    // simulated height must not recheck expiry or decrypt this input again.
                    let mut tx = sample_seismic_tx(&setup, "authenticated plaintext");
                    tx.seismic_elements.signed_read = true;
                    tx.seismic_elements.expires_at_block = 50;
                    // Re-encrypt after changing AEAD metadata, as real ingress would receive it.
                    let tx = sample_seismic_tx_with_elements(
                        &setup,
                        "authenticated plaintext",
                        tx.seismic_elements,
                    );
                    let encrypted = get_tx_envelope(&setup, tx);
                    let plaintext = encrypted
                        .plaintext_copy(&setup.purpose_keys.tx_io.secret_key(), setup.signer)
                        .unwrap();
                    let recovered = Recovered::new_unchecked(&plaintext, setup.signer);
                    let mut successful = false;
                    let result = if use_result_closure {
                        executor
                            .execute_transaction_with_result_closure(recovered, |result| {
                                successful = result.is_success();
                            })
                            .map(Some)
                    } else {
                        executor.execute_transaction_with_commit_condition(recovered, |result| {
                            successful = result.is_success();
                            CommitChanges::Yes
                        })
                    };
                    if enabled {
                        assert!(result.is_ok(), "trusted plaintext should execute: {result:?}");
                        assert!(successful, "plaintext must not be decrypted a second time");
                        let expected = first_tx_accumulator(plaintext.trie_hash());
                        assert_eq!(
                            executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(),
                            &expected
                        );
                        let (_, block) = executor.finish().unwrap();
                        assert_eq!(block.receipts.len(), 1);
                        assert!(block.receipts[0].status());
                    } else {
                        assert!(matches!(result, Err(BlockExecutionError::Validation(_))));
                        assert!(!successful, "wire intent alone must not enable the bypass");
                        assert_eq!(
                            executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(),
                            &B256::ZERO
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn simulation_factory_preserves_live_encrypted_validation_and_decryption() {
        for use_result_closure in [false, true] {
            for inspected in [false, true] {
                for (expired, corrupted) in [(false, false), (true, false), (false, true)] {
                    let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
                    let setup = setup_test(&mut state);
                    let mut cfg = CfgEnv::new_with_spec(SeismicSpecId::MERCURY);
                    cfg.chain_id = 5124;
                    let mut evm = setup.evm_factory.create_evm(
                        &mut state,
                        EvmEnv::new(
                            cfg,
                            BlockEnv { number: U256::from(100), ..Default::default() },
                        ),
                    );
                    evm.set_inspector_enabled(inspected);
                    let factory = setup.executor_factory.clone().with_plaintext_signed_reads();
                    let mut executor = factory.create_executor(evm, setup.ctx.clone());
                    executor.apply_pre_execution_changes().unwrap();
                    let mut tx = sample_seismic_tx(&setup, "ordinary encrypted replay");
                    if expired {
                        tx.seismic_elements.expires_at_block = 50;
                    }
                    if corrupted {
                        tx.input = Bytes::from_static(b"invalid ciphertext");
                    }
                    let envelope = get_tx_envelope(&setup, tx);
                    let recovered = Recovered::new_unchecked(&envelope, setup.signer);
                    let mut successful = None;
                    let result = if use_result_closure {
                        executor
                            .execute_transaction_with_result_closure(recovered, |result| {
                                successful = Some(result.is_success());
                            })
                            .map(Some)
                    } else {
                        executor.execute_transaction_with_commit_condition(recovered, |result| {
                            successful = Some(result.is_success());
                            CommitChanges::Yes
                        })
                    };
                    if expired {
                        assert!(matches!(result, Err(BlockExecutionError::Validation(_))));
                        assert_eq!(successful, None);
                        assert_eq!(
                            executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(),
                            &B256::ZERO
                        );
                    } else {
                        assert!(result.is_ok(), "encrypted replay should be processed: {result:?}");
                        assert_eq!(successful, Some(!corrupted));
                        assert_eq!(
                            executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(),
                            &first_tx_accumulator(envelope.trie_hash())
                        );
                        let (_, block) = executor.finish().unwrap();
                        assert_eq!(block.receipts.len(), 1);
                        assert_eq!(block.receipts[0].status(), !corrupted);
                        assert!(block.gas_used > 21_000);
                    }
                }
            }
        }
    }

    #[test]
    fn uncommitted_plaintext_signed_read_does_not_advance_accumulator_or_nonce() {
        for inspected in [false, true] {
            let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
            let setup = setup_test(&mut state);
            let mut evm = setup.evm_factory.create_evm(
                &mut state,
                EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
            );
            evm.set_inspector_enabled(inspected);
            let factory = setup.executor_factory.clone().with_plaintext_signed_reads();
            let mut executor = factory.create_executor(evm, setup.ctx.clone());
            executor.apply_pre_execution_changes().unwrap();
            let mut elements = sample_seismic_tx(&setup, "unused").seismic_elements;
            elements.signed_read = true;
            let envelope = get_tx_envelope(
                &setup,
                sample_seismic_tx_with_elements(&setup, "authenticated plaintext", elements),
            );
            let plaintext = envelope
                .plaintext_copy(&setup.purpose_keys.tx_io.secret_key(), setup.signer)
                .unwrap();
            let result = executor
                .execute_transaction_with_commit_condition(
                    Recovered::new_unchecked(&plaintext, setup.signer),
                    |result| {
                        assert!(result.is_success());
                        CommitChanges::No
                    },
                )
                .unwrap();
            assert_eq!(result, None);
            assert_eq!(executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(), &B256::ZERO);
            executor
                .execute_transaction_with_result_closure(
                    Recovered::new_unchecked(&plaintext, setup.signer),
                    |result| assert!(result.is_success()),
                )
                .expect("the same nonce must remain usable after a non-commit");
            assert_eq!(
                executor.evm_mut().seismic_chain_mut().tx_hash_accumulator(),
                &first_tx_accumulator(plaintext.trie_hash())
            );
            let (_, block) = executor.finish().unwrap();
            assert_eq!(block.receipts.len(), 1);
        }
    }

    fn sign_seismic_tx(tx: &TxSeismic, signing_key: &SigningKey) -> Signature {
        let _signature = signing_key
            .clone()
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .expect("Failed to sign");

        let recoverid = _signature.1;
        let _signature = _signature.0;

        let signature = Signature::new(
            U256::from_be_slice(&_signature.r().to_bytes()),
            U256::from_be_slice(&_signature.s().to_bytes()),
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
        purpose_keys: PurposeKeys,
        keyring: Arc<PurposeKeyring>,
        encryption_pubkey: PublicKey,
        encryption_sk: SecretKey,
        encryption_nonce: Nonce,
        evm_factory: SeismicEvmFactory,
    }

    fn setup_test<'a, DB: Database>(state: &mut State<DB>) -> SetupTest<'a> {
        let rng = &mut rand::thread_rng();
        let signing_key = SigningKey::random(rng);
        let pubkey = signing_key.verifying_key();
        let signer = public_key_to_address(*pubkey);

        let encryption_sk = SecretKey::new(rng);
        let secp = Secp256k1::new();
        let encryption_pubkey = PublicKey::from_secret_key(&secp, &encryption_sk);

        let mock_keys = PurposeKeys::well_known();
        let keyring = Arc::new(PurposeKeyring::single_epoch(mock_keys.clone()));
        let evm_factory = SeismicEvmFactory::new(keyring.clone());

        state.increment_balances(vec![(signer, 1000000000000000000)]).unwrap();
        let executor_factory = SeismicBlockExecutorFactory::new(
            SeismicAlloyReceiptBuilder::default(),
            SeismicChainHardforks::seismic_mainnet(),
            evm_factory.clone(),
            keyring.clone(),
        );

        let ctx = SeismicBlockExecutionCtx {
            withdrawals: None,
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
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
            keyring,
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
            .client_encrypt(&pt_bytes, &setup.purpose_keys.tx_io.public_key(), &setup.encryption_sk)
            .unwrap();

        TxSeismic {
            chain_id: tx_metadata.legacy_fields.chain_id,
            nonce: tx_metadata.legacy_fields.nonce,
            gas_price: 1000000000,
            gas_limit: 1000000,
            gas_payment: seismic_alloy_consensus::GasPayment::Auto,
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

    #[derive(Debug, thiserror::Error)]
    #[error("injected freshness block-hash database error at block {0}")]
    struct FreshnessDbError(u64);

    impl DBErrorMarker for FreshnessDbError {}

    /// All unrelated reads succeed, so the fault can only originate in the freshness scan.
    #[derive(Debug, Default)]
    struct FreshnessDb {
        inner: InMemoryDB,
        fail_at: Option<u64>,
        block_hash_reads: Vec<u64>,
    }

    impl RevmDatabase for FreshnessDb {
        type Error = FreshnessDbError;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.inner.basic(address).unwrap())
        }

        fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(self.inner.code_by_hash(hash).unwrap())
        }

        fn storage(
            &mut self,
            address: Address,
            index: U256,
        ) -> Result<FlaggedStorage, Self::Error> {
            Ok(self.inner.storage(address, index).unwrap())
        }

        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            self.block_hash_reads.push(number);
            if self.fail_at == Some(number) {
                return Err(FreshnessDbError(number));
            }
            Ok(B256::repeat_byte(number as u8))
        }
    }

    fn assert_freshness_hash_read_outcome(
        use_result_closure: bool,
        inspected: bool,
        fail_read: bool,
    ) {
        // At block 100 the parent is checked directly, then the scan first reads block 98.
        // This anchor is valid when the database is healthy, not a genuinely stale hash.
        let db = FreshnessDb { fail_at: fail_read.then_some(98), ..Default::default() };
        let mut state = StateBuilder::new_with_database(db).build();
        let setup = setup_test(&mut state);
        let mut cfg = CfgEnv::new_with_spec(SeismicSpecId::MERCURY);
        cfg.chain_id = 5124;
        let mut evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(cfg, BlockEnv { number: U256::from(100), ..Default::default() }),
        );
        evm.set_inspector_enabled(inspected);
        let mut executor = SeismicBlockExecutor::new(
            evm,
            setup.ctx.clone(),
            SeismicChainHardforks::seismic_mainnet(),
            SeismicAlloyReceiptBuilder::default(),
        );
        executor.apply_pre_execution_changes().unwrap();

        let tx = sample_seismic_tx_with_elements(
            &setup,
            "historical anchor",
            TxSeismicElements {
                encryption_pubkey: setup.encryption_pubkey,
                encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
                message_version: 0,
                recent_block_hash: B256::repeat_byte(98),
                expires_at_block: 1000,
                signed_read: false,
            },
        );
        let envelope = get_tx_envelope(&setup, tx);
        let recovered = Recovered::new_unchecked(&envelope, setup.signer);
        let mut executed_successfully = false;
        let result = if use_result_closure {
            executor
                .execute_transaction_with_result_closure(recovered, |result| {
                    executed_successfully = result.is_success();
                })
                .map(Some)
        } else {
            executor.execute_transaction_with_commit_condition(recovered, |result| {
                executed_successfully = result.is_success();
                CommitChanges::Yes
            })
        };
        if !fail_read {
            assert!(result.is_ok(), "the historical anchor must be valid: {result:?}");
            assert!(executed_successfully, "the healthy control must execute successfully");
            assert!(executor.evm().ctx().error.is_ok());
            assert_eq!(
                executor.evm().ctx().journaled_state.database.database.block_hash_reads,
                vec![98],
            );
            return;
        }

        let error = result.expect_err("the historical hash read must fail");
        assert!(
            matches!(&error, BlockExecutionError::Internal(_)),
            "a local DB failure must not invalidate the transaction: {error:?}; pending: {:?}",
            executor.evm().ctx().error,
        );
        assert_eq!(
            error.to_string(),
            format!(
                "block hash lookup for block 98 failed while validating transaction {}: \
                 injected freshness block-hash database error at block 98",
                envelope.trie_hash(),
            ),
        );
        let BlockExecutionError::Internal(internal) = &error else {
            unreachable!("the error classification was checked above");
        };
        let lookup = internal.downcast_other::<BlockHashLookupError<FreshnessDbError>>().unwrap();
        assert_eq!(lookup.number, 98);
        assert_eq!(lookup.tx_hash, envelope.trie_hash());
        let source =
            core::error::Error::source(lookup).expect("the provider error must be preserved");
        assert_eq!(source.downcast_ref::<FreshnessDbError>().unwrap().0, 98);
        assert!(executor.evm().ctx().error.is_ok(), "the DB error must not remain pending");
        assert_eq!(
            executor.evm().ctx().journaled_state.database.database.block_hash_reads,
            vec![98],
            "the scan must stop at the first DB error",
        );

        // A parent-anchored tx makes no historical reads. It must not inherit the failed
        // scan's error, and nonce 0 must remain usable because the failed tx never executed.
        let retry = sample_seismic_tx(&setup, "parent anchor");
        let envelope = get_tx_envelope(&setup, retry);
        let recovered = Recovered::new_unchecked(&envelope, setup.signer);
        let result = if use_result_closure {
            executor.execute_transaction_with_result_closure(recovered, |_| {}).map(Some)
        } else {
            executor.execute_transaction_with_commit_condition(recovered, |_| CommitChanges::Yes)
        };
        assert!(result.is_ok(), "the next valid tx must not inherit the DB error: {result:?}");
        assert!(executor.evm().ctx().error.is_ok());
        assert_eq!(
            executor.evm().ctx().journaled_state.database.database.block_hash_reads,
            vec![98]
        );
    }

    #[test]
    fn test_freshness_db_error_commit_condition() {
        assert_freshness_hash_read_outcome(false, false, true);
    }

    #[test]
    fn test_freshness_db_error_result_closure() {
        assert_freshness_hash_read_outcome(true, false, true);
    }

    #[test]
    fn test_freshness_db_error_inspected_commit_condition() {
        assert_freshness_hash_read_outcome(false, true, true);
    }

    #[test]
    fn test_freshness_db_error_inspected_result_closure() {
        assert_freshness_hash_read_outcome(true, true, true);
    }

    #[test]
    fn test_freshness_historical_anchor_with_healthy_db() {
        for use_result_closure in [false, true] {
            for inspected in [false, true] {
                assert_freshness_hash_read_outcome(use_result_closure, inspected, false);
            }
        }
    }

    #[test]
    fn watcher_update_cannot_change_selected_block_keys() {
        for use_result_closure in [false, true] {
            let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
            let setup = setup_test(&mut state);
            let env = EvmEnv::new(
                CfgEnv::new_with_spec(SeismicSpecId::MERCURY),
                BlockEnv { number: U256::from(100), ..Default::default() },
            );
            let evm = setup.evm_factory.create_evm(&mut state, env);
            let mut ctx = setup.ctx.clone();
            ctx.parent_beacon_block_root = Some(B256::ZERO);
            let mut executor = setup.executor_factory.create_executor(evm, ctx);
            executor.apply_pre_execution_changes().unwrap();
            let keyring = setup.keyring.clone();
            std::thread::spawn(move || {
                let sk = SecretKey::from_byte_array(&[42; 32]).unwrap();
                keyring
                    .insert_epoch(
                        1,
                        PurposeKeys {
                            tx_io: secp256k1::Keypair::from_secret_key(&Secp256k1::new(), &sk),
                            rng_ikm: [42; 64],
                        },
                    )
                    .unwrap();
                keyring.replace_canonical_view(CanonicalRotationView {
                    head_hash: B256::repeat_byte(1),
                    head_number: 100,
                    schedule: RotationSchedule::from_entries([RotationEntry {
                        epoch: 1,
                        activation_block: 100,
                        announced_at_block: 10,
                    }])
                    .unwrap(),
                });
            })
            .join()
            .unwrap();
            let envelope = get_tx_envelope(&setup, sample_seismic_tx(&setup, "frozen epoch zero"));
            let recovered = Recovered::new_unchecked(&envelope, setup.signer);
            if use_result_closure {
                executor.execute_transaction_with_result_closure(recovered, |_| {}).unwrap();
            } else {
                executor.execute_transaction(recovered).unwrap();
            }
            let (_, result) = executor.finish().unwrap();
            assert!(
                result.receipts.first().unwrap().status(),
                "watcher must not change decryption mid-block"
            );
        }
    }

    #[test]
    fn transactions_fail_before_block_key_initialization() {
        let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
        let setup = setup_test(&mut state);
        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());
        let envelope = get_tx_envelope(&setup, sample_seismic_tx(&setup, "must not execute"));
        let recovered = Recovered::new_unchecked(&envelope, setup.signer);
        assert!(executor
            .execute_transaction(recovered)
            .unwrap_err()
            .to_string()
            .contains("uninitialized"));
        let recovered = Recovered::new_unchecked(&envelope, setup.signer);
        assert!(executor
            .execute_transaction_with_result_closure(recovered, |_| {})
            .unwrap_err()
            .to_string()
            .contains("uninitialized"));
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
        executor.apply_pre_execution_changes().unwrap();

        let plaintext = "hello world";
        let tx_seismic = sample_seismic_tx(&setup, plaintext);
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);
        executor.execute_transaction(recovered).unwrap();
    }

    /// A Seismic tx whose freshness window has passed must surface as a *validation* error
    /// (`BlockValidationError::InvalidTx`), not a fatal `Internal` error — that classification is
    /// what lets the payload builder skip it and block import respond INVALID.
    #[test]
    fn test_expired_tx_is_validation_error() {
        let db = InMemoryDB::default();
        let mut state = StateBuilder::new_with_database(db).build();
        let setup = setup_test(&mut state);

        // Block 100 with a tx that expired at block 50.
        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(100);
        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());
        executor.apply_pre_execution_changes().unwrap();

        let elements = TxSeismicElements {
            encryption_pubkey: setup.encryption_pubkey,
            encryption_nonce: U96::from_be_slice(&setup.encryption_nonce.0),
            message_version: 0,
            // Matches setup_test's parent_hash, so only the expiry check fails.
            recent_block_hash: B256::ZERO,
            expires_at_block: 50,
            signed_read: false,
        };
        let tx = sample_seismic_tx_with_elements(&setup, "hello world", elements);
        let tx_envelope = get_tx_envelope(&setup, tx);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);

        let result = executor.execute_transaction(recovered);
        assert!(
            matches!(
                result,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx { .. }))
            ),
            "expired tx must be a validation (InvalidTx) error, got: {result:?}"
        );
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
        executor.apply_pre_execution_changes().unwrap();

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
        executor.apply_pre_execution_changes().unwrap();

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
        executor.apply_pre_execution_changes().unwrap();

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
        executor.apply_pre_execution_changes().unwrap();

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
        executor.apply_pre_execution_changes().unwrap();

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

    /// Executing a block at or past a rotation's activation without that epoch's
    /// keys must be a hard block-execution error (the node stalls until its
    /// rotation watcher fetches the keys) — never a silent fallback to another
    /// epoch's keys.
    #[test]
    fn test_missing_epoch_keys_stall_block_execution() {
        let db = rotation_db();
        let mut state = StateBuilder::new_with_database(db).build();
        let setup = setup_test(&mut state);

        // Parent-state epoch 1 activates at block 100; its keys are not inserted.
        // No canonical schedule publication is required for discovery.

        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(100);
        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());
        let result = executor.apply_pre_execution_changes();
        assert!(result.unwrap_err().is_retryable(), "missing epoch keys must be retryable");
        assert_eq!(setup.keyring.requested_epochs(), vec![1]);
    }

    /// After a rotation activates (with its keys fetched), a transaction still
    /// encrypted to the *previous* epoch's network key decrypts to garbage and is
    /// handled as a metered decryption failure — while the same block's executor
    /// decrypts new-epoch ciphertexts fine.
    #[test]
    fn test_old_epoch_ciphertext_fails_after_activation() {
        let db = rotation_db();
        let mut state = StateBuilder::new_with_database(db).build();
        let setup = setup_test(&mut state);

        // Epoch 1 (a fresh, valid keypair) activates at block 100.
        let rng = &mut rand::thread_rng();
        let epoch1_sk = SecretKey::new(rng);
        let epoch1_tx_io = secp256k1::Keypair::from_secret_key(&Secp256k1::new(), &epoch1_sk);
        setup
            .keyring
            .insert_epoch(1, PurposeKeys { tx_io: epoch1_tx_io, rng_ikm: [7u8; 64] })
            .unwrap();

        let mut block_env = BlockEnv::default();
        block_env.number = U256::from(100);
        let evm = setup.evm_factory.create_evm(
            &mut state,
            EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), block_env),
        );
        let mut executor = setup.executor_factory.create_executor(evm, setup.ctx.clone());
        executor.apply_pre_execution_changes().unwrap();

        // sample_seismic_tx encrypts to the epoch-0 network key: at block 100 the
        // executor decrypts with epoch 1's key, so this must take the
        // decryption-failed path (metered, failed receipt), not succeed.
        let tx_seismic = sample_seismic_tx(&setup, "encrypted to the old epoch");
        let tx_envelope = get_tx_envelope(&setup, tx_seismic);
        let recovered = Recovered::new_unchecked(&tx_envelope, setup.signer);
        executor.execute_transaction(recovered).expect("old-epoch tx is metered, not fatal");

        let (_, block_result) = executor.finish().expect("finish should succeed");
        assert_eq!(block_result.receipts.len(), 1);
        assert!(
            !block_result.receipts[0].status(),
            "old-epoch ciphertext must produce a failed (decryption_failed) receipt"
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
        executor.apply_pre_execution_changes().unwrap();

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
        executor.apply_pre_execution_changes().unwrap();

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

    /// A `SeismicEvmFactory`-built EVM must expose the tx-type precompile at `0x6A`: a
    /// top-level call returns the transaction's EIP-2718 type byte as a 32-byte word — the
    /// value `TxUtils.txType()` reads via `staticcall`. This is the standalone-crate proof
    /// that re-pinning to the precompile revm actually wires `0x6A` into the factory.
    #[test]
    fn test_txtype_precompile_via_factory() {
        fn probe(tx_type: u8, signed_read: bool, selector: &[u8]) -> U256 {
            let mut state = StateBuilder::new_with_database(InMemoryDB::default()).build();
            let keyring = Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known()));
            let evm_factory = SeismicEvmFactory::new(keyring);
            let mut evm = evm_factory.create_evm(
                &mut state,
                EvmEnv::new(CfgEnv::new_with_spec(SeismicSpecId::MERCURY), BlockEnv::default()),
            );

            let tx = SeismicTransaction {
                base: TxEnv {
                    caller: Address::ZERO,
                    kind: TxKind::Call(Address::with_last_byte(0x6A)),
                    nonce: 0,
                    gas_limit: 1_000_000,
                    gas_price: 0,
                    gas_priority_fee: None,
                    value: U256::ZERO,
                    data: Bytes::copy_from_slice(selector),
                    chain_id: None,
                    access_list: Default::default(),
                    blob_hashes: Vec::new(),
                    max_fee_per_blob_gas: 0,
                    tx_type,
                    authorization_list: Default::default(),
                },
                tx_hash: Default::default(),
                decryption_failed: false,
                signed_read,
                gas_payment: seismic_revm::GasPayment::Auto,
            };

            let out = match evm.transact(tx).expect("transact to 0x6A").result {
                ExecutionResult::Success { output, .. } => output.into_data(),
                other => panic!("call to 0x6A precompile failed: {other:?}"),
            };
            assert_eq!(out.len(), 32, "tx-context precompile must return a 32-byte word");
            U256::from_be_slice(&out)
        }

        // Empty selector → the raw EIP-2718 tx type.
        assert_eq!(probe(0x4A, false, &[]), U256::from(0x4Au64));
        assert_eq!(probe(0, false, &[]), U256::ZERO);

        // Selector 0x01 → `signed_read && tx_type == 74`.
        assert_eq!(probe(0x4A, true, &[0x01]), U256::from(1u64));
        assert_eq!(probe(0x4A, false, &[0x01]), U256::ZERO);
        // Raw signed_read=true on a non-Seismic type is normalized to 0 (isSignedRead =>
        // isSeismicTx).
        assert_eq!(probe(0, true, &[0x01]), U256::ZERO);
        assert_eq!(probe(2, true, &[0x01]), U256::ZERO);
    }
}
