//! Seismic hardforks.

use alloy_hardforks::hardfork;
use alloy_hardforks::EthereumHardfork;
use alloy_hardforks::EthereumHardforks;
use alloy_hardforks::ForkCondition;

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
        if fork < EthereumHardfork::Prague {
            // We assume that Seismic chains were launched with all forks before Prague activated.
            ForkCondition::Block(0)
        } else {
            ForkCondition::Never
        }
    }
}
