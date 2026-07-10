//! Seismic security policy for RPC block and state overrides.
//!
//! This module centralizes the checks that decide which override fields are
//! permitted on Seismic. The apply functions in [`crate::overrides`] are pure
//! mechanism; the policy lives here so it can be audited in one place.
//!
//! Policy: fields that could be used to disclose shielded storage (contract
//! code, storage slots) are rejected with an explicit error rather than
//! silently filtered..

use crate::overrides::StateOverrideError;
use alloy_primitives::Address;
use alloy_rpc_types_eth::{state::AccountOverride, BlockOverrides};
use revm::Database;

/// Validates that the account override only touches permitted fields.
///
/// Returns the override to apply, or an error if a forbidden field is set.
///
/// # SECURITY
///
/// This function is responsible for rejecting overrides of fields that could
/// disclose shielded storage, or for filtering/clamping overrides to safe
/// values where partial fulfillment is truthful.
pub fn validate_account_override<DB>(
    account: Address,
    account_override: &AccountOverride,
    _db: &DB,
) -> Result<AccountOverride, StateOverrideError<DB::Error>>
where
    DB: Database,
{
    // CHECK: Ensure that the account override does not override contract code.
    // Allowing code overrides could lead to arbitrary code executing at the
    // account address, disclosing shielded storage.
    if account_override.code.is_some() {
        return Err(StateOverrideError::CodeOverrideNotPermitted(account));
    }

    // CHECK: Ensure that the account override does not override storage, which
    // could lead to manipulating contract state (e.g. access-control slots) to
    // disclose shielded storage.
    if account_override.state.is_some() || account_override.state_diff.is_some() {
        return Err(StateOverrideError::StorageOverrideNotPermitted(account));
    }

    Ok(account_override.clone())
}

/// Validates the given block overrides.
///
/// Currently a pass-through: no block override field gates access to shielded
/// data. This is the hook point for future block-level policy (e.g. clamping
/// timestamp or gas-limit manipulation).
pub fn validate_block_overrides<DB>(
    overrides: &BlockOverrides,
    _db: &DB,
) -> Result<BlockOverrides, StateOverrideError<DB::Error>>
where
    DB: Database,
{
    Ok(overrides.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes, map::HashMap, B256, U256};
    use revm::database::{CacheDB, EmptyDB};

    const ACCOUNT: Address = address!("0x1234567890123456789012345678901234567890");

    #[test]
    fn code_override_rejected() {
        let db = CacheDB::new(EmptyDB::new());
        let acc_override = AccountOverride::default().with_code(bytes!("0x60016001"));
        let result = validate_account_override(ACCOUNT, &acc_override, &db);
        assert!(matches!(result, Err(StateOverrideError::CodeOverrideNotPermitted(_))));
    }

    #[test]
    fn storage_overrides_rejected() {
        let db = CacheDB::new(EmptyDB::new());
        let mut storage = HashMap::<B256, B256>::default();
        storage.insert(B256::from(U256::from(1)), B256::from(U256::from(100)));

        let state_override = AccountOverride::default().with_state(storage.clone());
        let result = validate_account_override(ACCOUNT, &state_override, &db);
        assert!(matches!(result, Err(StateOverrideError::StorageOverrideNotPermitted(_))));

        let diff_override = AccountOverride::default().with_state_diff(storage);
        let result = validate_account_override(ACCOUNT, &diff_override, &db);
        assert!(matches!(result, Err(StateOverrideError::StorageOverrideNotPermitted(_))));
    }

    #[test]
    fn block_overrides_pass_through() {
        let db = CacheDB::new(EmptyDB::new());
        let overrides = BlockOverrides { time: Some(12345), ..Default::default() };
        let validated = validate_block_overrides(&overrides, &db).unwrap();
        assert_eq!(validated.time, Some(12345));
    }
}
