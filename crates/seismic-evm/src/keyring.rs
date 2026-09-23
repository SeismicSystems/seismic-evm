//! Epoch-keyed purpose-key management.
//!
//! Purpose keys (the tx-io keypair and the RNG ikm) are derived per **epoch** by the
//! key custodian. Epochs advance via on-chain rotation announcements (see
//! `docs/design/purpose-key-rotation.md` in seismic-reth); the epoch active for a
//! block is a deterministic function of chain state, so execution selects keys
//! through the [`PurposeKeyring`] per block instead of holding a single static key
//! bundle.
//!
//! Key material is additive and shared; canonical metadata is replaceable and
//! used only for RPC/pool policy. Execution resolves its epoch through the registry
//! decoder against its own parent-state database and requests material by epoch.

use crate::PurposeKeys;
use alloy_primitives::B256;
use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    vec::Vec,
};

/// One announced key rotation — the node-side mirror of a `KeyRotationRegistry`
/// storage entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationEntry {
    /// The epoch this rotation activates. Entry `i` of the registry array is always
    /// epoch `i + 1` (epoch 0 is the genesis epoch and never appears on-chain).
    pub epoch: u64,
    /// The first block executed with this epoch's keys.
    pub activation_block: u64,
    /// The block at which the rotation was announced on-chain. Always strictly less
    /// than `activation_block` (the contract enforces a minimum delay).
    pub announced_at_block: u64,
}

/// Errors validating or extending a [`RotationSchedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    /// An entry's epoch is not the next dense epoch.
    NonDenseEpoch {
        /// The epoch the entry carries.
        got: u64,
        /// The epoch required at this position.
        expected: u64,
    },
    /// An entry's activation does not come after the previous entry's.
    NonMonotonicActivation {
        /// The previous entry's activation block.
        prev: u64,
        /// The offending entry's activation block.
        got: u64,
    },
    /// An entry activates at or before its own announcement.
    ActivationNotAfterAnnouncement {
        /// The offending epoch.
        epoch: u64,
        /// Its activation block.
        activation_block: u64,
        /// Its announcement block.
        announced_at_block: u64,
    },
    /// A proposed extension disagrees with an existing entry on the same branch.
    /// Canonical reorg reconciliation replaces a schedule instead of extending it.
    DivergentHistory {
        /// Index of the first disagreeing entry.
        index: usize,
    },
    /// A newer schedule is shorter than the already-known one.
    Regression {
        /// Entries already known.
        have: usize,
        /// Entries in the purportedly newer schedule.
        got: usize,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonDenseEpoch { got, expected } => {
                write!(f, "rotation entry has epoch {got}, expected dense epoch {expected}")
            }
            Self::NonMonotonicActivation { prev, got } => {
                write!(f, "rotation activation {got} is not after the previous activation {prev}")
            }
            Self::ActivationNotAfterAnnouncement {
                epoch,
                activation_block,
                announced_at_block,
            } => write!(
                f,
                "epoch {epoch} activates at block {activation_block}, which is not after its announcement at block {announced_at_block}"
            ),
            Self::DivergentHistory { index } => {
                write!(f, "rotation history diverged at entry {index}")
            }
            Self::Regression { have, got } => {
                write!(f, "rotation history regressed from {have} entries to {got}")
            }
        }
    }
}

impl core::error::Error for ScheduleError {}

/// The keyring has no key material for an epoch it was asked to serve.
///
/// For consensus consumers this must be a hard failure with no fallback: executing
/// with another epoch's keys forks the state root (wrong `rng_ikm`) or flips
/// `decryption_failed` receipts (wrong `tx_io_sk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingEpochKeys {
    /// The epoch whose keys are missing.
    pub epoch: u64,
    /// The block that needed them.
    pub block: u64,
}

impl fmt::Display for MissingEpochKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "purpose keys for epoch {} are not in the keyring (needed for block {}); waiting on a custodian fetch",
            self.epoch, self.block
        )
    }
}

impl core::error::Error for MissingEpochKeys {}

/// An epoch already holds key material that differs from a new insertion — the
/// custodian derivation is deterministic, so this can only be a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochKeyConflict {
    /// The conflicting epoch.
    pub epoch: u64,
}

impl fmt::Display for EpochKeyConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch {} already holds different purpose keys", self.epoch)
    }
}

impl core::error::Error for EpochKeyConflict {}

/// Failure to insert purpose-key material into a keyring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InsertEpochError {
    /// Simulation handles may read shared material but cannot insert it.
    #[error("simulation keyrings cannot insert purpose keys")]
    Simulation,
    /// The epoch already holds different key material.
    #[error(transparent)]
    Conflict(#[from] EpochKeyConflict),
}

/// The append-only rotation history: entry `i` is epoch `i + 1`, activations strictly
/// increase, and every entry activates after its announcement. Carries no key
/// material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationSchedule(Vec<RotationEntry>);

impl RotationSchedule {
    /// An empty schedule: every block is epoch 0.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Builds a schedule from entries, validating every invariant.
    pub fn from_entries(
        entries: impl IntoIterator<Item = RotationEntry>,
    ) -> Result<Self, ScheduleError> {
        let mut schedule = Self::new();
        for entry in entries {
            schedule.push(entry)?;
        }
        Ok(schedule)
    }

    /// Appends the next rotation, enforcing the schedule invariants.
    pub fn push(&mut self, entry: RotationEntry) -> Result<(), ScheduleError> {
        let expected = (self.0.len() as u64).saturating_add(1);
        if entry.epoch != expected {
            return Err(ScheduleError::NonDenseEpoch { got: entry.epoch, expected });
        }
        if entry.activation_block <= entry.announced_at_block {
            return Err(ScheduleError::ActivationNotAfterAnnouncement {
                epoch: entry.epoch,
                activation_block: entry.activation_block,
                announced_at_block: entry.announced_at_block,
            });
        }
        if let Some(last) = self.0.last() {
            if entry.activation_block <= last.activation_block {
                return Err(ScheduleError::NonMonotonicActivation {
                    prev: last.activation_block,
                    got: entry.activation_block,
                });
            }
        }
        self.0.push(entry);
        Ok(())
    }

    /// Extends this schedule to match `newer`, which must be a strict extension of it
    /// (identical prefix). Returns the number of entries appended.
    pub fn extend_to(&mut self, newer: &Self) -> Result<usize, ScheduleError> {
        if newer.0.len() < self.0.len() {
            return Err(ScheduleError::Regression { have: self.0.len(), got: newer.0.len() });
        }
        for (index, (known, incoming)) in self.0.iter().zip(newer.0.iter()).enumerate() {
            if known != incoming {
                return Err(ScheduleError::DivergentHistory { index });
            }
        }
        let mut appended = 0;
        for entry in newer.0.iter().skip(self.0.len()) {
            self.push(*entry)?;
            appended += 1;
        }
        Ok(appended)
    }

    /// The epoch active for `block`: the greatest announced epoch whose activation is
    /// at or before `block`, or 0 if none (the normative epoch-for-block function).
    pub fn epoch_at_block(&self, block: u64) -> u64 {
        self.0
            .iter()
            .rev()
            .find(|entry| entry.activation_block <= block)
            .map(|entry| entry.epoch)
            .unwrap_or(0)
    }

    /// The soonest rotation that has not yet activated as of `tip`, if any.
    pub fn pending_after(&self, tip: u64) -> Option<&RotationEntry> {
        self.0.iter().find(|entry| entry.activation_block > tip)
    }

    /// Number of announced rotations (the registry array length).
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no rotation has ever been announced.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// All announced rotations, in epoch order.
    pub fn entries(&self) -> &[RotationEntry] {
        &self.0
    }
}

/// Replaceable canonical metadata, read from one specific head's state.
/// This view is for RPC and pool policy, never for block execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalRotationView {
    /// Hash whose post-state supplied the schedule.
    pub head_hash: B256,
    /// Number of that head (may decrease on reorg).
    pub head_number: u64,
    /// Full schedule in that head's post-state.
    pub schedule: RotationSchedule,
}

struct KeyringState {
    keys: BTreeMap<u64, PurposeKeys>,
    requested: BTreeSet<u64>,
}

/// Owned key selection fixed for the lifetime of one block execution attempt.
#[derive(Debug, Clone)]
pub struct BlockKeySelection {
    /// Epoch resolved from the actual parent state.
    pub epoch: u64,
    /// The keys used for both RNG and every transaction's decryption.
    pub keys: PurposeKeys,
}

/// Whether a handle may mutate shared key material and enqueue fetch requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringMode {
    Live,
    Simulation,
}

/// Shared, swappable purpose-key state: the rotation schedule and the key material
/// for every known epoch. Cheap to clone behind an `Arc`; all methods take `&self`.
///
/// The block executor resolves its epoch from parent state, then uses
/// [`PurposeKeyring::select_epoch`]. It never selects from canonical metadata.
pub struct PurposeKeyring {
    inner: Arc<RwLock<KeyringState>>,
    canonical: RwLock<CanonicalRotationView>,
    mode: KeyringMode,
}

impl fmt::Debug for PurposeKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.read();
        // Deliberately omits the key material.
        f.debug_struct("PurposeKeyring")
            .field("mode", &self.mode)
            .field("canonical", &self.canonical_view())
            .field("epochs_with_keys", &state.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PurposeKeyring {
    /// A keyring holding only epoch 0 with an empty schedule — the pre-rotation
    /// state every node boots with, and the whole story for dev nodes and tests.
    pub fn single_epoch(keys: PurposeKeys) -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeyringState {
                keys: BTreeMap::from([(0, keys)]),
                requested: BTreeSet::new(),
            })),
            canonical: RwLock::new(CanonicalRotationView::default()),
            mode: KeyringMode::Live,
        }
    }

    /// Creates a simulation handle sharing only additive key material.
    ///
    /// It inherits no canonical schedule and cannot insert material or enqueue fetch
    /// requests. Each simulated block resolves its schedule from its own parent overlay.
    /// Material fetched by the live worker can become available, but can never change an
    /// already-initialized execution attempt's epoch or keys.
    pub fn snapshot(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            canonical: RwLock::new(CanonicalRotationView::default()),
            mode: KeyringMode::Simulation,
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, KeyringState> {
        self.inner.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, KeyringState> {
        self.inner.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The epoch at `block` in the canonical metadata snapshot. This is not an
    /// execution API: a competing branch may have a different epoch at that height.
    pub fn epoch_for_block(&self, block: u64) -> u64 {
        self.canonical_view().schedule.epoch_at_block(block)
    }

    /// The epoch and keys active at the last known canonical tip. This is what RPC
    /// advertises (`seismic_getTeePublicKey`) and decrypts signed reads with.
    pub fn current(&self) -> Result<(u64, PurposeKeys), MissingEpochKeys> {
        let view = self.canonical_view();
        let epoch = view.schedule.epoch_at_block(view.head_number);
        self.keys_for_epoch(epoch)
            .map(|keys| (epoch, keys))
            .ok_or(MissingEpochKeys { epoch, block: view.head_number })
    }

    /// The soonest announced-but-not-yet-activated rotation as of the known tip, as
    /// `(epoch, activation_block)`. Drives the pool's expiry boundary rule.
    pub fn pending(&self) -> Option<(u64, u64)> {
        let view = self.canonical_view();
        view.schedule
            .pending_after(view.head_number)
            .map(|entry| (entry.epoch, entry.activation_block))
    }

    /// The head number in the canonical view (may decrease after reconciliation).
    pub fn known_tip(&self) -> u64 {
        self.canonical_view().head_number
    }

    /// Inserts key material for an epoch. Idempotent: re-inserting identical keys
    /// returns `Ok(false)`; inserting *different* keys for a known epoch is a bug
    /// and errors without overwriting. Simulation handles reject all insertions,
    /// including identical material, without modifying shared keys or fetch requests.
    pub fn insert_epoch(&self, epoch: u64, keys: PurposeKeys) -> Result<bool, InsertEpochError> {
        if self.mode == KeyringMode::Simulation {
            return Err(InsertEpochError::Simulation);
        }
        let mut state = self.write();
        match state.keys.get(&epoch) {
            Some(existing) if keys_equal(existing, &keys) => Ok(false),
            Some(_) => Err(EpochKeyConflict { epoch }.into()),
            None => {
                state.keys.insert(epoch, keys);
                state.requested.remove(&epoch);
                Ok(true)
            }
        }
    }

    /// Number of rotations in the known schedule.
    pub fn schedule_len(&self) -> usize {
        self.canonical_view().schedule.len()
    }

    /// The keys for a specific epoch, if fetched.
    pub fn keys_for_epoch(&self, epoch: u64) -> Option<PurposeKeys> {
        self.read().keys.get(&epoch).cloned()
    }

    /// The block at which `epoch` activates per the known schedule. Epoch 0 is the
    /// genesis epoch (activation 0); an epoch beyond the schedule is unknown.
    pub fn activation_block_of(&self, epoch: u64) -> Option<u64> {
        if epoch == 0 {
            return Some(0);
        }
        self.canonical_view()
            .schedule
            .entries()
            .iter()
            .find(|entry| entry.epoch == epoch)
            .map(|entry| entry.activation_block)
    }

    /// Atomically publishes a complete canonical view, including shorter histories,
    /// same-length replacements and lower heads. The serialized watcher is the writer.
    pub fn replace_canonical_view(&self, view: CanonicalRotationView) {
        *self.canonical.write().unwrap_or_else(|err| err.into_inner()) = view;
    }

    /// One coherent RPC/pool metadata snapshot. Key inventory is additive and separate.
    pub fn canonical_view(&self) -> CanonicalRotationView {
        self.canonical.read().unwrap_or_else(|err| err.into_inner()).clone()
    }

    /// Selects keys for an epoch already resolved from the execution's parent state.
    /// Missing live-execution epochs are deduplicated for the background fetcher;
    /// isolated simulations cannot enqueue work, even though key material is shared.
    pub fn select_epoch(
        &self,
        epoch: u64,
        block: u64,
    ) -> Result<BlockKeySelection, MissingEpochKeys> {
        let mut state = self.write();
        if let Some(keys) = state.keys.get(&epoch) {
            return Ok(BlockKeySelection { epoch, keys: keys.clone() });
        }
        if self.mode == KeyringMode::Live {
            state.requested.insert(epoch);
        }
        Err(MissingEpochKeys { epoch, block })
    }

    /// Missing execution-requested epochs; retained across failed fetch attempts.
    pub fn requested_epochs(&self) -> Vec<u64> {
        self.read().requested.iter().copied().collect()
    }

    /// Deduplicated union of canonical and execution-requested missing epochs.
    pub fn unfetched_epochs(&self) -> Vec<u64> {
        let view = self.canonical_view();
        let state = self.read();
        view.schedule
            .entries()
            .iter()
            .map(|entry| entry.epoch)
            .chain(state.requested.iter().copied())
            .filter(|epoch| !state.keys.contains_key(epoch))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Scheduled epochs (1..=schedule len) whose keys are not yet in the keyring —
    /// the rotation watcher's fetch work-list. Epoch 0 is excluded (seeded at boot).
    pub fn unfetched_scheduled_epochs(&self) -> Vec<u64> {
        let view = self.canonical_view();
        let state = self.read();
        view.schedule
            .entries()
            .iter()
            .map(|entry| entry.epoch)
            .filter(|epoch| !state.keys.contains_key(epoch))
            .collect()
    }
}

/// Field-wise equality; [`PurposeKeys`] does not derive `PartialEq` itself.
fn keys_equal(a: &PurposeKeys, b: &PurposeKeys) -> bool {
    a.tx_io == b.tx_io && a.rng_ikm == b.rng_ikm
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn simulation_shares_only_material_and_cannot_request_fetches() {
        let live = PurposeKeyring::single_epoch(test_keys(1));
        live.replace_canonical_view(CanonicalRotationView {
            head_hash: B256::repeat_byte(1),
            head_number: 120,
            schedule: schedule(&[(1, 100, 10), (2, 200, 110)]),
        });
        live.insert_epoch(1, test_keys(2)).unwrap();
        let snapshot = live.snapshot();
        assert_eq!(snapshot.canonical_view(), CanonicalRotationView::default());
        assert!(keys_equal(&snapshot.keys_for_epoch(1).unwrap(), &live.keys_for_epoch(1).unwrap()));
        assert!(snapshot.select_epoch(2, 200).is_err());
        assert!(live.requested_epochs().is_empty());
        live.insert_epoch(2, test_keys(3)).unwrap();
        assert_eq!(snapshot.select_epoch(2, 200).unwrap().keys.rng_ikm, [3; 64]);
        assert_eq!(snapshot.canonical_view(), CanonicalRotationView::default());
    }

    #[test]
    fn simulation_cannot_insert_material_or_clear_live_fetch_requests() {
        let live = PurposeKeyring::single_epoch(test_keys(1));
        assert!(live.select_epoch(1, 100).is_err());

        // Taking another snapshot must not restore live permissions.
        for simulation in [live.snapshot(), live.snapshot().snapshot()] {
            for (epoch, keys) in [(0, test_keys(1)), (0, test_keys(2)), (1, test_keys(2))] {
                assert_eq!(simulation.insert_epoch(epoch, keys), Err(InsertEpochError::Simulation));
            }
            assert!(keys_equal(&live.keys_for_epoch(0).unwrap(), &test_keys(1)));
            assert!(live.keys_for_epoch(1).is_none());
            assert_eq!(live.requested_epochs(), vec![1]);
        }

        let simulation = live.snapshot();
        live.insert_epoch(1, test_keys(2)).unwrap();
        assert!(live.requested_epochs().is_empty());
        assert!(keys_equal(&simulation.select_epoch(1, 100).unwrap().keys, &test_keys(2)));
    }

    fn view(head_number: u64) -> CanonicalRotationView {
        CanonicalRotationView {
            head_number,
            head_hash: B256::from(U256::from(head_number)),
            schedule: schedule(&[(1, 100, 10)]),
        }
    }

    fn test_keys(seed: u8) -> PurposeKeys {
        let sk = SecretKey::from_byte_array(&[seed; 32]).unwrap();
        let tx_io = secp256k1::Keypair::from_secret_key(&Secp256k1::new(), &sk);
        PurposeKeys { tx_io, rng_ikm: [seed; 64] }
    }

    fn schedule(entries: &[(u64, u64, u64)]) -> RotationSchedule {
        RotationSchedule::from_entries(entries.iter().map(|&(epoch, activation, announced)| {
            RotationEntry { epoch, activation_block: activation, announced_at_block: announced }
        }))
        .unwrap()
    }

    #[test]
    fn empty_schedule_is_epoch_zero_everywhere() {
        let s = RotationSchedule::new();
        assert_eq!(s.epoch_at_block(0), 0);
        assert_eq!(s.epoch_at_block(u64::MAX), 0);
        assert!(s.pending_after(0).is_none());
    }

    #[test]
    fn epoch_flips_exactly_at_activation() {
        let s = schedule(&[(1, 100, 10)]);
        assert_eq!(s.epoch_at_block(99), 0);
        assert_eq!(s.epoch_at_block(100), 1);
        assert_eq!(s.epoch_at_block(101), 1);
    }

    #[test]
    fn multi_rotation_selects_greatest_activated() {
        let s = schedule(&[(1, 100, 10), (2, 300, 200)]);
        assert_eq!(s.epoch_at_block(0), 0);
        assert_eq!(s.epoch_at_block(100), 1);
        assert_eq!(s.epoch_at_block(299), 1);
        assert_eq!(s.epoch_at_block(300), 2);
    }

    #[test]
    fn schedule_rejects_invalid_entries() {
        let mut s = RotationSchedule::new();
        assert_eq!(
            s.push(RotationEntry { epoch: 2, activation_block: 100, announced_at_block: 10 }),
            Err(ScheduleError::NonDenseEpoch { got: 2, expected: 1 })
        );
        assert_eq!(
            s.push(RotationEntry { epoch: 1, activation_block: 10, announced_at_block: 10 }),
            Err(ScheduleError::ActivationNotAfterAnnouncement {
                epoch: 1,
                activation_block: 10,
                announced_at_block: 10
            })
        );
        s.push(RotationEntry { epoch: 1, activation_block: 100, announced_at_block: 10 }).unwrap();
        assert_eq!(
            s.push(RotationEntry { epoch: 2, activation_block: 100, announced_at_block: 50 }),
            Err(ScheduleError::NonMonotonicActivation { prev: 100, got: 100 })
        );
    }

    #[test]
    fn extend_to_appends_only_the_tail_and_rejects_divergence() {
        let mut known = schedule(&[(1, 100, 10)]);
        let newer = schedule(&[(1, 100, 10), (2, 300, 200)]);
        assert_eq!(known.extend_to(&newer), Ok(1));
        assert_eq!(known, newer);
        assert_eq!(known.extend_to(&newer), Ok(0));

        let mut known = schedule(&[(1, 100, 10)]);
        let diverged = schedule(&[(1, 101, 10)]);
        assert_eq!(known.extend_to(&diverged), Err(ScheduleError::DivergentHistory { index: 0 }));
        assert_eq!(
            known.extend_to(&RotationSchedule::new()),
            Err(ScheduleError::Regression { have: 1, got: 0 })
        );
    }

    /// State-height independence: extending the schedule with later announcements
    /// never changes the epoch of an old block.
    #[test]
    fn later_announcements_never_change_old_blocks() {
        let mut s = schedule(&[(1, 100, 10)]);
        let before: Vec<u64> = (0..150).map(|b| s.epoch_at_block(b)).collect();
        s.extend_to(&schedule(&[(1, 100, 10), (2, 300, 200)])).unwrap();
        let after: Vec<u64> = (0..150).map(|b| s.epoch_at_block(b)).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn single_epoch_keyring_serves_epoch_zero_everywhere() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        assert_eq!(keyring.epoch_for_block(u64::MAX), 0);
        assert_eq!(keyring.select_epoch(0, 12345).unwrap().keys.rng_ikm, [1; 64]);
        let (epoch, keys) = keyring.current().unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(keys.rng_ikm, [1; 64]);
        assert_eq!(keyring.pending(), None);
        assert!(keyring.unfetched_scheduled_epochs().is_empty());
    }

    #[test]
    fn missing_epoch_is_a_hard_error_until_fetched() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        keyring.replace_canonical_view(view(99));
        assert_eq!(keyring.select_epoch(0, 99).unwrap().keys.rng_ikm, [1; 64]);
        assert_eq!(
            keyring.select_epoch(1, 100).map(|_| ()),
            Err(MissingEpochKeys { epoch: 1, block: 100 })
        );
        assert_eq!(keyring.unfetched_scheduled_epochs(), vec![1]);

        assert!(keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert_eq!(keyring.select_epoch(1, 100).unwrap().keys.rng_ikm, [2; 64]);
        assert!(keyring.unfetched_scheduled_epochs().is_empty());
    }

    #[test]
    fn insert_is_idempotent_and_conflicts_error() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        assert!(keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert!(!keyring.insert_epoch(1, test_keys(2)).unwrap());
        assert_eq!(
            keyring.insert_epoch(1, test_keys(3)),
            Err(InsertEpochError::Conflict(EpochKeyConflict { epoch: 1 }))
        );
        assert_eq!(keyring.keys_for_epoch(1).unwrap().rng_ikm, [2; 64]);
    }

    #[test]
    fn current_and_pending_follow_the_reconciled_head() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        keyring.insert_epoch(1, test_keys(2)).unwrap();

        keyring.replace_canonical_view(view(50));
        assert_eq!(keyring.current().unwrap().0, 0);
        assert_eq!(keyring.pending(), Some((1, 100)));

        keyring.replace_canonical_view(view(100));
        assert_eq!(keyring.current().unwrap().0, 1);
        assert_eq!(keyring.pending(), None);

        // Lower canonical heads are allowed on a reorg.
        keyring.replace_canonical_view(view(10));
        assert_eq!(keyring.current().unwrap().0, 0);
    }

    #[test]
    fn activation_block_of_reports_the_schedule() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        assert_eq!(keyring.activation_block_of(0), Some(0));
        assert_eq!(keyring.activation_block_of(1), None);
        keyring.replace_canonical_view(view(50));
        assert_eq!(keyring.activation_block_of(1), Some(100));
    }

    #[test]
    fn requests_are_deduplicated_and_survive_reconciliation() {
        let keyring = PurposeKeyring::single_epoch(test_keys(1));
        for _ in 0..3 {
            assert!(keyring.select_epoch(1, 200).is_err());
        }
        assert_eq!(keyring.requested_epochs(), vec![1]);
        keyring.replace_canonical_view(CanonicalRotationView::default());
        assert_eq!(keyring.unfetched_epochs(), vec![1]);
        keyring.insert_epoch(1, test_keys(2)).unwrap();
        assert!(keyring.unfetched_epochs().is_empty());
        assert!(keyring.requested_epochs().is_empty());
        assert_eq!(keyring.select_epoch(1, 200).unwrap().epoch, 1);
    }
}
