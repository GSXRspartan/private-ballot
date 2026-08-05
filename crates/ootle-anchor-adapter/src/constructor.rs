//! Offline anchor-transaction constructor trait (Section H).
//!
//! [`AnchorTransactionConstructor`] translates the project-owned build request
//! into an Ootle build result plus project-owned inspection evidence, entirely
//! offline. The pinned unsigned transaction lives inside the returned
//! [`OotleAnchorBuildResultV1`] and is therefore reachable only through this leaf
//! adapter crate; the anchor and anchor-transport crates never see an Ootle type.
//! A future walletd adapter (Slice 4A6) can depend on this crate and consume the
//! unsigned transaction internally.

use crate::build::{OotleAnchorBuildResultV1, build_unsigned_anchor_transaction};
use crate::errors::OotleAnchorAdapterError;
use crate::request::OotleAnchorTransactionBuildRequestV1;

/// Offline constructor from a project build request to an Ootle build result.
pub trait AnchorTransactionConstructor {
    /// Constructs the unsigned anchor transaction, evidence, and walletd
    /// preparation DTO for one build request.
    ///
    /// # Errors
    ///
    /// Returns an [`OotleAnchorAdapterError`] if construction or inspection fails.
    fn construct(
        &self,
        request: &OotleAnchorTransactionBuildRequestV1,
    ) -> Result<OotleAnchorBuildResultV1, OotleAnchorAdapterError>;
}

/// The pinned Ootle implementation of [`AnchorTransactionConstructor`].
///
/// It is a zero-sized, side-effect-free value: constructing a transaction is a
/// pure transformation of the request, touches no network, and holds no state or
/// secret.
#[derive(Debug, Clone, Copy, Default)]
pub struct PinnedOotleAnchorTransactionConstructor;

impl AnchorTransactionConstructor for PinnedOotleAnchorTransactionConstructor {
    fn construct(
        &self,
        request: &OotleAnchorTransactionBuildRequestV1,
    ) -> Result<OotleAnchorBuildResultV1, OotleAnchorAdapterError> {
        build_unsigned_anchor_transaction(request)
    }
}
