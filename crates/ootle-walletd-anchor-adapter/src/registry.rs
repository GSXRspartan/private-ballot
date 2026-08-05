//! In-memory local request registry and its recovery snapshot (Section G).
//!
//! The registry tracks, per project request: the walletd request identifier, the
//! frozen binding, the decision state, a deterministic registration sequence, and
//! the last bounded diagnostic code. It stores no wallet secret, no private key,
//! no archive content, and no ballot. Durable on-disk persistence is deliberately
//! deferred; the deterministic [`WalletdAnchorSnapshotV1`] plus `from_snapshots`
//! import is sufficient to prove restart safety offline.

use std::collections::BTreeMap;

use tari_cc_private_ballot_anchor_transport::AnchorRequestId;

use crate::binding::WalletdAnchorBindingV1;
use crate::identifiers::WalletdRequestId;

/// Project-owned decision state of a stored walletd request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletdRequestDecisionV1 {
    /// Created and awaiting an approval decision.
    Prepared,
    /// Approved by an approver and not yet submitted.
    Approved,
    /// Rejected by an approver. Terminal for this adapter.
    Rejected,
    /// The approval window closed before a terminal decision was reached.
    Expired,
}

impl WalletdRequestDecisionV1 {
    /// Returns the stable machine-readable decision code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
        }
    }
}

/// One stored request record.
#[derive(Debug, Clone)]
pub(crate) struct WalletdRequestRecord {
    pub(crate) walletd_request_id: WalletdRequestId,
    pub(crate) binding: WalletdAnchorBindingV1,
    pub(crate) decision: WalletdRequestDecisionV1,
    pub(crate) sequence: u64,
    pub(crate) last_diagnostic: Option<&'static str>,
}

/// Deterministic recovery snapshot for one stored request.
///
/// It preserves only what a restart needs to resume the lifecycle safely, and
/// nothing sensitive. It is comparable and order-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdAnchorSnapshotV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    decision: WalletdRequestDecisionV1,
    sequence: u64,
    last_diagnostic: Option<&'static str>,
}

impl WalletdAnchorSnapshotV1 {
    /// Builds a recovery snapshot.
    #[must_use]
    pub fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
        decision: WalletdRequestDecisionV1,
        sequence: u64,
        last_diagnostic: Option<&'static str>,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            decision,
            sequence,
            last_diagnostic,
        }
    }

    /// Returns the project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the recorded decision state.
    #[must_use]
    pub const fn decision(&self) -> WalletdRequestDecisionV1 {
        self.decision
    }

    /// Returns the deterministic registration sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn last_diagnostic(&self) -> Option<&'static str> {
        self.last_diagnostic
    }
}

/// In-memory registry of prepared walletd anchor requests.
#[derive(Debug, Default)]
pub struct LocalWalletdAnchorRegistry {
    records: BTreeMap<AnchorRequestId, WalletdRequestRecord>,
    by_walletd: BTreeMap<i32, AnchorRequestId>,
    sequence_counter: u64,
}

impl LocalWalletdAnchorRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a freshly prepared request in the `Prepared` state.
    pub(crate) fn register_prepared(
        &mut self,
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> u64 {
        let sequence = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);

        self.by_walletd
            .insert(walletd_request_id.value(), project_request_id.clone());
        self.records.insert(
            project_request_id,
            WalletdRequestRecord {
                walletd_request_id,
                binding,
                decision: WalletdRequestDecisionV1::Prepared,
                sequence,
                last_diagnostic: None,
            },
        );
        sequence
    }

    /// Returns the stored record for a project request identifier.
    pub(crate) fn record(
        &self,
        project_request_id: &AnchorRequestId,
    ) -> Option<&WalletdRequestRecord> {
        self.records.get(project_request_id)
    }

    /// Sets the decision state of a stored request.
    pub(crate) fn set_decision(
        &mut self,
        project_request_id: &AnchorRequestId,
        decision: WalletdRequestDecisionV1,
    ) {
        if let Some(record) = self.records.get_mut(project_request_id) {
            record.decision = decision;
        }
    }

    /// Records the last bounded diagnostic code for a stored request.
    pub(crate) fn set_diagnostic(
        &mut self,
        project_request_id: &AnchorRequestId,
        diagnostic: &'static str,
    ) {
        if let Some(record) = self.records.get_mut(project_request_id) {
            record.last_diagnostic = Some(diagnostic);
        }
    }

    /// Returns whether a walletd request identifier is already tracked.
    #[must_use]
    pub fn contains_walletd_request(&self, walletd_request_id: WalletdRequestId) -> bool {
        self.by_walletd.contains_key(&walletd_request_id.value())
    }

    /// Returns the decision state for a project request identifier.
    #[must_use]
    pub fn decision(
        &self,
        project_request_id: &AnchorRequestId,
    ) -> Option<WalletdRequestDecisionV1> {
        self.records
            .get(project_request_id)
            .map(|record| record.decision)
    }

    /// Returns a recovery snapshot for one stored request.
    #[must_use]
    pub fn snapshot(
        &self,
        project_request_id: &AnchorRequestId,
    ) -> Option<WalletdAnchorSnapshotV1> {
        let record = self.records.get(project_request_id)?;
        Some(WalletdAnchorSnapshotV1::new(
            project_request_id.clone(),
            record.walletd_request_id,
            record.binding.clone(),
            record.decision,
            record.sequence,
            record.last_diagnostic,
        ))
    }

    /// Returns recovery snapshots for every stored request, in request order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<WalletdAnchorSnapshotV1> {
        self.records
            .keys()
            .filter_map(|project_request_id| self.snapshot(project_request_id))
            .collect()
    }

    /// Rebuilds a registry from recovery snapshots, as after a restart.
    ///
    /// The sequence counter is restored to one past the highest imported
    /// sequence, so newly prepared requests continue deterministically.
    #[must_use]
    pub fn from_snapshots(snapshots: Vec<WalletdAnchorSnapshotV1>) -> Self {
        let mut registry = Self::new();
        let mut highest_sequence: Option<u64> = None;

        for snapshot in snapshots {
            highest_sequence = Some(match highest_sequence {
                Some(current) => current.max(snapshot.sequence()),
                None => snapshot.sequence(),
            });

            registry.by_walletd.insert(
                snapshot.walletd_request_id().value(),
                snapshot.project_request_id().clone(),
            );
            registry.records.insert(
                snapshot.project_request_id().clone(),
                WalletdRequestRecord {
                    walletd_request_id: snapshot.walletd_request_id(),
                    binding: snapshot.binding().clone(),
                    decision: snapshot.decision(),
                    sequence: snapshot.sequence(),
                    last_diagnostic: snapshot.last_diagnostic(),
                },
            );
        }

        registry.sequence_counter = match highest_sequence {
            Some(highest) => highest.wrapping_add(1),
            None => 0,
        };
        registry
    }
}
