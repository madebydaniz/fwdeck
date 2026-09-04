//! Identity-bearing publication envelope for authoritative firewall snapshots.

use std::num::NonZeroU64;
use std::ops::Deref;
use std::sync::Arc;

use super::RefreshId;
use crate::domain::FirewallSnapshot;

/// Monotonic process-local identity for an authoritative snapshot publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotGeneration(NonZeroU64);

impl SnapshotGeneration {
    #[must_use]
    pub(crate) const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Correlates a published snapshot with the refresh that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotIdentity {
    refresh_id: RefreshId,
    generation: SnapshotGeneration,
}

impl SnapshotIdentity {
    #[must_use]
    pub(crate) const fn new(refresh_id: RefreshId, generation: SnapshotGeneration) -> Self {
        Self {
            refresh_id,
            generation,
        }
    }

    #[must_use]
    pub const fn refresh_id(self) -> RefreshId {
        self.refresh_id
    }

    #[must_use]
    pub const fn generation(self) -> SnapshotGeneration {
        self.generation
    }
}

/// An immutable authoritative snapshot plus its exact publication identity.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedSnapshot {
    identity: SnapshotIdentity,
    snapshot: Arc<FirewallSnapshot>,
}

impl ObservedSnapshot {
    #[must_use]
    pub(crate) const fn new(identity: SnapshotIdentity, snapshot: Arc<FirewallSnapshot>) -> Self {
        Self { identity, snapshot }
    }

    #[must_use]
    pub const fn identity(&self) -> SnapshotIdentity {
        self.identity
    }

    #[must_use]
    pub fn snapshot(&self) -> &FirewallSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn snapshot_arc(&self) -> &Arc<FirewallSnapshot> {
        &self.snapshot
    }

    #[must_use]
    pub fn into_snapshot(self) -> Arc<FirewallSnapshot> {
        self.snapshot
    }
}

impl Deref for ObservedSnapshot {
    type Target = FirewallSnapshot;

    fn deref(&self) -> &Self::Target {
        self.snapshot()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SnapshotIdentityExhausted;

#[derive(Debug)]
pub(crate) struct SnapshotPublisher {
    next_generation: Option<NonZeroU64>,
}

impl SnapshotPublisher {
    pub(crate) const fn new() -> Self {
        Self {
            next_generation: Some(NonZeroU64::MIN),
        }
    }

    pub(crate) fn publish(
        &mut self,
        refresh_id: RefreshId,
        snapshot: Arc<FirewallSnapshot>,
    ) -> Result<ObservedSnapshot, SnapshotIdentityExhausted> {
        let generation = self.next_generation.ok_or(SnapshotIdentityExhausted)?;
        self.next_generation = generation.get().checked_add(1).and_then(NonZeroU64::new);

        Ok(ObservedSnapshot::new(
            SnapshotIdentity::new(refresh_id, SnapshotGeneration::new(generation)),
            snapshot,
        ))
    }

    #[cfg(test)]
    const fn with_next_generation(next_generation: NonZeroU64) -> Self {
        Self {
            next_generation: Some(next_generation),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Arc;

    use super::*;
    use crate::application::RefreshId;
    use crate::domain::mock;

    #[test]
    fn equal_snapshot_values_receive_distinct_publication_identities() {
        let snapshot = Arc::new(mock::sample().unwrap());
        let mut publisher = SnapshotPublisher::new();

        let first = publisher
            .publish(RefreshId::new(7), Arc::clone(&snapshot))
            .unwrap();
        let second = publisher
            .publish(RefreshId::new(8), Arc::clone(&snapshot))
            .unwrap();

        assert_eq!(first.snapshot(), second.snapshot());
        assert_eq!(first.identity().refresh_id(), RefreshId::new(7));
        assert_eq!(first.identity().generation().get(), 1);
        assert_eq!(second.identity().refresh_id(), RefreshId::new(8));
        assert_eq!(second.identity().generation().get(), 2);
        assert_ne!(first.identity(), second.identity());
        assert!(Arc::ptr_eq(first.snapshot_arc(), second.snapshot_arc()));
    }

    #[test]
    fn exhausted_generation_never_wraps_or_reuses_an_identity() {
        let snapshot = Arc::new(mock::sample().unwrap());
        let mut publisher = SnapshotPublisher::with_next_generation(NonZeroU64::MAX);

        let last = publisher
            .publish(RefreshId::new(9), Arc::clone(&snapshot))
            .unwrap();
        assert_eq!(last.identity().generation().get(), u64::MAX);
        assert_eq!(
            publisher.publish(RefreshId::new(10), snapshot),
            Err(SnapshotIdentityExhausted),
        );
    }

    #[test]
    fn consuming_envelope_returns_the_same_snapshot_allocation() {
        let snapshot = Arc::new(mock::sample().unwrap());
        let mut publisher = SnapshotPublisher::new();
        let observed = publisher
            .publish(RefreshId::new(1), Arc::clone(&snapshot))
            .unwrap();

        assert!(Arc::ptr_eq(&observed.into_snapshot(), &snapshot));
    }
}
