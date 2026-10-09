//! Timestamp precision through the factory, wrapper, system caller and block executor.

use alloy_eips::{
    eip2935::HISTORY_STORAGE_ADDRESS, eip4788::BEACON_ROOTS_ADDRESS,
    eip7002::WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use alloy_evm::{
    block::{BlockExecutor, SystemCaller},
    eth::{spec::EthSpec, EthBlockExecutionCtx, EthBlockExecutor},
    Evm, EvmFactory,
};
use alloy_primitives::{bytes, Address, Bytes, TxKind, B256, U256};
use alloy_seismic_evm::{
    block::SeismicAlloyReceiptBuilder, PurposeKeyring, PurposeKeys, SeismicBlockEnv, SeismicEvm,
    SeismicEvmEnv, SeismicEvmFactory,
};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    database::{InMemoryDB, State},
    inspector::NoOpInspector,
    state::{AccountInfo, Bytecode},
    Database as _,
};
use seismic_revm::{transaction::abstraction::SeismicTransaction, SeismicSpecId};
use std::sync::Arc;

const CALLER: Address = Address::repeat_byte(0x11);
const CONTRACT: Address = Address::repeat_byte(0x22);
const CANCUN_TIMESTAMP: u64 = 1_710_338_135;
const PRAGUE_TIMESTAMP: u64 = 1_746_612_311;

fn factory() -> SeismicEvmFactory {
    SeismicEvmFactory::new(Arc::new(PurposeKeyring::single_epoch(PurposeKeys::well_known())))
}

fn env(seconds: u64, part: u64) -> SeismicEvmEnv {
    SeismicEvmEnv::new(
        CfgEnv::new_with_spec(SeismicSpecId::MERCURY),
        SeismicBlockEnv {
            inner: BlockEnv {
                number: U256::from(20_000_000),
                timestamp: U256::from(seconds),
                gas_limit: 40_000_000,
                basefee: 7,
                ..Default::default()
            },
            timestamp_millis_part: part,
        },
    )
}

fn contract_db(address: Address, code: Bytes) -> InMemoryDB {
    let code = Bytecode::new_legacy(code);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        address,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            nonce: 1,
            ..Default::default()
        },
    );
    db.insert_account_info(
        CALLER,
        AccountInfo { balance: U256::from(1_000_000_000), ..Default::default() },
    );
    db
}

fn create_evm(
    factory: &SeismicEvmFactory,
    db: InMemoryDB,
    env: SeismicEvmEnv,
    inspected: bool,
) -> SeismicEvm<InMemoryDB, NoOpInspector> {
    if inspected {
        factory.create_evm_with_inspector(db, env, NoOpInspector)
    } else {
        factory.create_evm(db, env)
    }
}

fn call(contract: Address, data: Bytes) -> SeismicTransaction<TxEnv> {
    TxEnv {
        caller: CALLER,
        kind: TxKind::Call(contract),
        gas_limit: 100_000,
        gas_price: 7,
        data,
        ..Default::default()
    }
    .into()
}

#[test]
fn factory_and_finish_preserve_exact_timestamps_in_all_execution_modes() {
    let factory = factory();
    // Return TIMESTAMP and TIMESTAMPMS as two consecutive words.
    let code = bytes!("425f524b60205260405ff3");
    for inspected in [false, true] {
        for system_call in [false, true] {
            for (seconds, part) in
                [(0, 0), (0, 999), (1_800_000_000, 123), (1_800_000_000, 999), (1_800_000_001, 0)]
            {
                let input = env(seconds, part);
                let mut evm = create_evm(
                    &factory,
                    contract_db(CONTRACT, code.clone()),
                    input.clone(),
                    inspected,
                );
                assert_eq!(evm.block().timestamp, U256::from(seconds));
                assert_eq!(evm.ctx().block.timestamp_millis_part, part);

                let result = if system_call {
                    evm.transact_system_call(CALLER, CONTRACT, Bytes::new())
                } else {
                    evm.transact(call(CONTRACT, Bytes::new()))
                }
                .unwrap()
                .result;
                assert!(result.is_success(), "{result:?}");
                let output = result.output().unwrap();
                assert_eq!(output.len(), 64);
                assert_eq!(U256::from_be_slice(&output[..32]), U256::from(seconds));
                assert_eq!(U256::from_be_slice(&output[32..]), U256::from(seconds * 1000 + part));

                let (db, finished) = evm.finish();
                assert_eq!(
                    finished.block_env, input.block_env,
                    "system calls must restore the standard environment without losing its part"
                );
                let restored = create_evm(&factory, db, finished, !inspected);
                assert_eq!(restored.ctx().block.timestamp_millis_part, part);
                assert_eq!(
                    restored.ctx().block.timestamp_millis(),
                    U256::from(seconds * 1000 + part)
                );
            }
        }
    }
}

#[test]
fn same_second_beacon_roots_survive_system_caller_and_factory_round_trips() {
    let factory = factory();
    // Seismic dev/testnet genesis bytecode, with TIMESTAMPMS in the write path.
    let code = bytes!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff4b064b81555f359062001fff015500");
    let seconds = 1_800_000_000;
    let entries = [(123, B256::repeat_byte(0x11)), (456, B256::repeat_byte(0x22))];
    for inspected in [false, true] {
        let mut db = contract_db(BEACON_ROOTS_ADDRESS, code.clone());
        let mut input = env(seconds, entries[0].0);
        for (part, root) in entries {
            input.block_env.timestamp_millis_part = part;
            let mut evm = create_evm(&factory, db, input, inspected);
            SystemCaller::new(EthSpec::mainnet())
                .apply_beacon_root_contract_call(Some(root), &mut evm)
                .unwrap();
            (db, input) = evm.finish();
            assert_eq!(input.block_env.timestamp_millis_part, part);
            input.block_env.number += U256::from(1);
        }

        let mut evm = create_evm(&factory, db, input, inspected);
        for (part, root) in entries {
            let millis = seconds * 1000 + part;
            let data = Bytes::copy_from_slice(&U256::from(millis).to_be_bytes::<32>());
            let result = evm.transact(call(BEACON_ROOTS_ADDRESS, data)).unwrap().result;
            assert!(result.is_success(), "root lookup for {millis}: {result:?}");
            assert_eq!(result.output().unwrap().as_ref(), root.as_slice());
        }
        let data = Bytes::copy_from_slice(&U256::from(seconds).to_be_bytes::<32>());
        let result = evm.transact(call(BEACON_ROOTS_ADDRESS, data)).unwrap().result;
        assert!(matches!(result, revm::context::result::ExecutionResult::Revert { .. }));
    }
}

#[test]
fn pre_block_system_call_activation_uses_seconds_not_full_millis() {
    let factory = factory();
    // Store the supplied parent root/hash in slot zero when called.
    let code = bytes!("5f355f5500");
    let parent = B256::repeat_byte(0x33);
    for inspected in [false, true] {
        for (address, activation) in
            [(BEACON_ROOTS_ADDRESS, CANCUN_TIMESTAMP), (HISTORY_STORAGE_ADDRESS, PRAGUE_TIMESTAMP)]
        {
            for (seconds, part, active) in
                [(activation - 1, 999, false), (activation, 0, true), (activation, 999, true)]
            {
                let mut evm = create_evm(
                    &factory,
                    contract_db(address, code.clone()),
                    env(seconds, part),
                    inspected,
                );
                let mut caller = SystemCaller::new(EthSpec::mainnet());
                if address == BEACON_ROOTS_ADDRESS {
                    caller.apply_beacon_root_contract_call(Some(parent), &mut evm).unwrap();
                } else {
                    caller.apply_blockhashes_contract_call(parent, &mut evm).unwrap();
                }
                let stored = evm.db_mut().storage(address, U256::ZERO).unwrap().value;
                assert_eq!(stored, if active { U256::from_be_bytes(parent.0) } else { U256::ZERO });
            }
        }
    }
}

#[test]
fn block_executor_prague_gate_uses_seconds_and_preserves_the_part() {
    let factory = factory();
    // Record the call, then return a 48-byte withdrawal request.
    let code = bytes!("60015f5560305ff3");
    for inspected in [false, true] {
        for (seconds, part, active) in [
            (PRAGUE_TIMESTAMP - 1, 999, false),
            (PRAGUE_TIMESTAMP, 0, true),
            (PRAGUE_TIMESTAMP, 999, true),
        ] {
            let db = contract_db(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, code.clone());
            let mut state = State::builder().with_database(db).build();
            let input = env(seconds, part);
            let mut evm = if inspected {
                factory.create_evm_with_inspector(&mut state, input.clone(), NoOpInspector)
            } else {
                factory.create_evm(&mut state, input.clone())
            };
            evm.initialize_keys().unwrap();
            let ctx = EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
            };
            let executor = EthBlockExecutor::new(
                evm,
                ctx,
                EthSpec::mainnet(),
                SeismicAlloyReceiptBuilder::default(),
            );
            let (mut evm, result) = executor.finish().unwrap();
            assert_eq!(!result.requests.is_empty(), active);
            evm.db_mut().basic(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS).unwrap();
            let stored = evm
                .db_mut()
                .storage(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, U256::ZERO)
                .unwrap()
                .value;
            assert_eq!(stored, U256::from(active));
            assert_eq!(evm.into_env().block_env, input.block_env);
        }
    }
}
