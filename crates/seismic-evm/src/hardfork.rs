// //! Seismic-Reth hard forks.
// extern crate alloc;

// use alloc::vec;
// use once_cell::sync::Lazy as LazyLock;
// use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};
// use alloy_primitives::uint;

// use alloy_hardforks::hardforks::hardfork;

// /// Seismic hardfork enum
// #[derive(Clone, Debug)]
// #[allow(missing_docs)]
// pub enum SeismicHardfork {
//     MERCURY,
// }

// impl Hardfork for SeismicHardfork {
//     fn name(&self) -> &'static str {
//         match self {
//             Self::MERCURY => "Mercury",
//         }
//     }
// }