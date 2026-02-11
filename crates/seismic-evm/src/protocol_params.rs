//! Seismic protocol parameter requests and system call configuration.
//!
//! This module contains all Seismic-specific protocol parameter logic:
//! - Protocol parameter contract address and request type
//! - Event parsing from transaction receipts
//! - System call gas limit constant

use alloc::{string::ToString, vec::Vec};
use alloy_consensus::TxReceipt;
use alloy_evm::block::BlockValidationError;
use alloy_primitives::{address, Address, Bytes, Log};
use alloy_sol_types::{sol, SolEvent};

/// Protocol parameters contract address for Seismic chains.
///
/// This contract is deployed at genesis and stores network-wide protocol
/// parameters that can be updated through governance or predefined schedules.
///
/// The same address is used across all Seismic networks (mainnet, dev, testnet).
/// Address ends with "Params" in hex: 0x506172616D73
pub const SEISMIC_PROTOCOL_PARAMS_CONTRACT: Address =
    address!("0000000000000000000000000000506172616D73");

/// The [EIP-7685](https://eips.ethereum.org/EIPS/eip-7685) request type for protocol param requests.
pub const PROTOCOL_PARAM_REQUEST_TYPE: u8 = 0xFF;

/// Gas limit for system calls (protocol param updates, deposits, etc.)
///
/// These calls are executed with gas_price = 0 and don't count against the
/// block gas limit. Used in `SeismicEvm::transact_system_call()`.
pub const SYSTEM_CALL_GAS_LIMIT: u64 = 30_000_000;

const PROTOCOL_PARAM_MAX_BYTES_SIZE: usize = 1 + 100;

sol! {
    #[allow(missing_docs)]
    event ProtocolParamEvent(
        uint8 param_id,
        bytes param
    );
}

/// Accumulate a protocol param request from a log. containing a [`ParamEvent`].
pub fn accumulate_protocol_param_from_log(log: &Log<ProtocolParamEvent>, out: &mut Vec<u8>) {
    out.reserve(PROTOCOL_PARAM_MAX_BYTES_SIZE);
    out.extend_from_slice(&[log.param_id]);
    out.extend_from_slice(log.param.as_ref());
}

/// Accumulate protocol params from an iterator of logs.
pub fn accumulate_protocol_params_from_logs<'a>(
    address: Address,
    logs: impl IntoIterator<Item = &'a Log>,
    out: &mut Vec<u8>,
) -> Result<(), BlockValidationError> {
    logs.into_iter()
        // filter logs by address
        .filter(|log| log.address == address)
        // explicitly filter logs by the ParamEvent's signature hash (first topic)
        .filter(|log| {
            // 0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5
            log.topics().first() == Some(&ProtocolParamEvent::SIGNATURE_HASH)
        })
        .try_for_each(|log| {
            // We assume that the log is valid because it was emitted by the
            // protocol params contract.
            let decoded_log =
                ProtocolParamEvent::decode_log(log).map_err(|err: alloy_sol_types::Error| {
                    BlockValidationError::ProtocolParamRequestDecode(err.to_string())
                })?;
            accumulate_protocol_param_from_log(&decoded_log, out);
            Ok(())
        })
}

/// Accumulate protocol params from a receipt. Iterates over the logs in the receipt
/// and accumulates the protocol param request bytestrings.
pub fn accumulate_protocol_params_from_receipt(
    address: Address,
    receipt: impl TxReceipt<Log = Log>,
    out: &mut Vec<u8>,
) -> Result<(), BlockValidationError> {
    accumulate_protocol_params_from_logs(address, receipt.logs(), out)
}

/// Accumulate protocol params from a list of receipts. Iterates over the logs in the
/// receipts and accumulates the param request bytestrings.
pub fn accumulate_protocol_params_from_receipts<'a, I, R>(
    address: Address,
    receipts: I,
    out: &mut Vec<u8>,
) -> Result<(), BlockValidationError>
where
    I: IntoIterator<Item = &'a R>,
    R: TxReceipt<Log = Log> + 'a,
{
    receipts
        .into_iter()
        .try_for_each(|receipt| accumulate_protocol_params_from_receipt(address, receipt, out))
}

/// Find protocol param logs in a list of receipts, and return the concatenated
/// param request bytestring.
///
/// The address of the protocol params contract is taken from the chain spec.
pub fn parse_protocol_params_from_receipts<'a, I, R>(
    receipts: I,
) -> Result<Bytes, BlockValidationError>
where
    I: IntoIterator<Item = &'a R>,
    R: TxReceipt<Log = Log> + 'a,
{
    let mut out = Vec::new();
    accumulate_protocol_params_from_receipts(SEISMIC_PROTOCOL_PARAMS_CONTRACT, receipts, &mut out)?;
    Ok(out.into())
}
