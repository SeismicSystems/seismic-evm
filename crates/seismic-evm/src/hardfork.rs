//! Seismic hardforks.

use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_hardforks::{hardfork, EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_primitives::Address;

hardfork!(
    /// The name of an seismic hardfork.
    ///
    /// When building a list of hardforks for a chain, it's still expected to mix with
    /// [`EthereumHardfork`].
    // #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    SeismicHardfork {
        /// Mercury
        Mercury,
    }
);

impl SeismicHardfork {
    /// Seismic Hardfork condiditions for mainnet.
    pub const fn seismic_mainnet() -> [(Self, ForkCondition); 1] {
        [(Self::Mercury, ForkCondition::Block(0))]
    }
}

/// Extends [`EthereumHardforks`] with seismic helper methods.
#[auto_impl::auto_impl(&, Arc)]
pub trait SeismicHardforks: EthereumHardforks {
    /// Retrieves [`ForkCondition`] by an [`SeismicHardfork`]. If `fork` is not present, returns
    /// [`ForkCondition::Never`].
    fn seismic_fork_activation(&self, fork: SeismicHardfork) -> ForkCondition;
}

/// A type allowing to configure activation [`ForkCondition`]s for a given list of
/// [`SeismicHardfork`]s.
#[derive(Debug, Clone)]
pub struct SeismicChainHardforks {
    /// Seismic hardfork activations.
    pub forks: Vec<(SeismicHardfork, ForkCondition)>,
}

impl SeismicChainHardforks {
    /// Creates a new [`OpChainHardforks`] with the given list of forks.
    pub fn new(forks: impl IntoIterator<Item = (SeismicHardfork, ForkCondition)>) -> Self {
        let mut forks = forks.into_iter().collect::<Vec<_>>();
        forks.sort();
        Self { forks }
    }

    /// Creates a new [`OpChainHardforks`] with OP mainnet configuration.
    pub fn seismic_mainnet() -> Self {
        Self::new(SeismicHardfork::seismic_mainnet())
    }
}

impl EthereumHardforks for SeismicChainHardforks {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        if fork <= EthereumHardfork::Prague {
            // We assume that Seismic chains were launched with all forks through Prague
            // activated. Prague itself must be included here (not just forks strictly
            // before it): seismic-reth's own hardfork schedule activates Prague at genesis
            // (ForkCondition::Timestamp(0)), and Mercury extends Prague's precompile set
            // (see seismic-revm's test_cancun_precompiles_in_mercury, which builds Mercury's
            // precompiles as a superset of Precompiles::prague()). Reporting Prague as never
            // active here caused EIP-6110/7002/7251 system calls in
            // EthBlockExecutor::finish (crates/evm/src/eth/block.rs) to be silently skipped
            // for any consumer using this Spec, since that gate is
            // `spec.is_prague_active_at_timestamp(..)`.
            ForkCondition::Block(0)
        } else {
            ForkCondition::Never
        }
    }
}

impl SeismicHardforks for SeismicChainHardforks {
    fn seismic_fork_activation(&self, _fork: SeismicHardfork) -> ForkCondition {
        ForkCondition::Block(0)
    }
}

impl EthExecutorSpec for SeismicChainHardforks {
    fn deposit_contract_address(&self) -> Option<Address> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the off-by-one in `ethereum_fork_activation`: the comparison used
    /// to be `fork < EthereumHardfork::Prague`, which excluded Prague itself and made
    /// `is_prague_active_at_timestamp` return false at every timestamp. That gate is exactly
    /// what `EthBlockExecutor::finish` (in `crates/evm/src/eth/block.rs`) checks before running
    /// the EIP-6110/7002/7251 system calls, so this silently skipped them for any consumer
    /// using this Spec.
    #[test]
    fn test_prague_active_at_genesis() {
        let hardforks = SeismicChainHardforks::seismic_mainnet();
        assert!(
            hardforks.is_prague_active_at_timestamp(0),
            "Prague must be active at genesis on Seismic chains -- seismic-reth's own \
             hardfork schedule activates Prague at ForkCondition::Timestamp(0), and Mercury \
             extends Prague's precompile set (see seismic-revm's \
             test_cancun_precompiles_in_mercury)"
        );
    }
}
