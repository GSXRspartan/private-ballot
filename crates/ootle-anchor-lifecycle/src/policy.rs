//! Bounded, deterministic polling / retry policy (Section B).
//!
//! [`PollingPolicy`] carries [`max_query_attempts`](PollingPolicy::max_query_attempts)
//! and an abstract backoff schedule expressed as attempt indices (unitless),
//! never as a wall-clock duration. It uses no `std::time`, no sleeping, no async,
//! and no randomness. It is advanced explicitly by the caller — one attempt per
//! [`AnchorLifecycleOrchestrator::advance_one_poll`](crate::AnchorLifecycleOrchestrator::advance_one_poll)
//! step — consuming exactly one attempt each time.
//!
//! The policy decides only *how many* times to re-query and *whether* the bound
//! is exhausted; it never decides finality. Finality is decided solely by the
//! receipt coordinator's report. On exhaustion the lifecycle transitions to a
//! resumable [`Unknown`](UnifiedAnchorLifecyclePhase::Unknown), never to a
//! permanent-failure terminal.
//!
//! [`BackoffSchedule`] is the abstract, wall-clock-free schedule of attempt
//! indices the policy permits. It is comparable and inspectable so a caller or
//! reviewer can confirm exactly which attempt indices are within the bound
//! without any timing assumption.

use core::iter;
use std::ops::RangeInclusive;

/// Abstract, wall-clock-free backoff schedule expressed as attempt indices.
///
/// The schedule is the ordered set of unitless attempt indices the policy
/// permits: `1, 2, …, max_query_attempts`. There is no duration, no exponential
/// growth, and no randomness — only the count of attempts and their indices. A
/// real wall-clock adapter (Slice 4A9) may map these indices to concrete
/// delays, but this crate never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffSchedule {
    max_query_attempts: u32,
}

impl BackoffSchedule {
    /// Builds a schedule permitting attempts `1..=max_query_attempts`.
    ///
    /// `max_query_attempts = 0` yields an empty schedule; the policy is
    /// immediately exhausted, which still maps to a resumable `Unknown`, never
    /// to a permanent failure.
    #[must_use]
    pub const fn new(max_query_attempts: u32) -> Self {
        Self { max_query_attempts }
    }

    /// Returns the maximum number of query attempts the schedule permits.
    #[must_use]
    pub const fn max_query_attempts(self) -> u32 {
        self.max_query_attempts
    }

    /// Returns whether a given attempt index is within the schedule.
    ///
    /// Attempt indices are 1-based. An index of `0` is never within the
    /// schedule.
    #[must_use]
    pub const fn contains(self, attempt_index: u32) -> bool {
        attempt_index != 0 && attempt_index <= self.max_query_attempts
    }

    /// Returns the ordered attempt indices the schedule permits.
    ///
    /// The returned iterator yields `1, 2, …, max_query_attempts`. It owns no
    /// state and performs no I/O.
    #[must_use]
    pub fn attempt_indices(self) -> RangeInclusive<u32> {
        1..=self.max_query_attempts
    }
}

/// Bounded, deterministic polling / retry policy.
///
/// Carries the [`BackoffSchedule`] and the number of attempts already consumed.
/// The policy is comparable and inspectable (`attempts_consumed`,
/// `attempts_remaining`, `is_exhausted`). It is advanced explicitly by the
/// caller through [`consume_one`](Self::consume_one), which consumes exactly one
/// attempt and reports whether the bound is now exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingPolicy {
    schedule: BackoffSchedule,
    attempts_consumed: u32,
}

impl PollingPolicy {
    /// Creates a fresh policy with zero attempts consumed.
    #[must_use]
    pub const fn new(max_query_attempts: u32) -> Self {
        Self {
            schedule: BackoffSchedule::new(max_query_attempts),
            attempts_consumed: 0,
        }
    }

    /// Restores a policy from a consumed count, as after a restart.
    ///
    /// `attempts_consumed` is clamped to `max_query_attempts` so a corrupted
    /// snapshot cannot report more attempts than the schedule permits. The
    /// resumed lifecycle continues polling within the *remaining* attempt bound.
    #[must_use]
    pub const fn from_consumed(max_query_attempts: u32, attempts_consumed: u32) -> Self {
        let clamped = if attempts_consumed > max_query_attempts {
            max_query_attempts
        } else {
            attempts_consumed
        };
        Self {
            schedule: BackoffSchedule::new(max_query_attempts),
            attempts_consumed: clamped,
        }
    }

    /// Returns the backoff schedule.
    #[must_use]
    pub const fn schedule(self) -> BackoffSchedule {
        self.schedule
    }

    /// Returns the maximum number of query attempts the policy permits.
    #[must_use]
    pub const fn max_query_attempts(self) -> u32 {
        self.schedule.max_query_attempts()
    }

    /// Returns the number of attempts consumed so far.
    #[must_use]
    pub const fn attempts_consumed(self) -> u32 {
        self.attempts_consumed
    }

    /// Returns the 1-based index the next attempt would have, or `max` if
    /// exhausted.
    #[must_use]
    pub const fn next_attempt_index(self) -> u32 {
        self.attempts_consumed.saturating_add(1)
    }

    /// Returns the number of attempts remaining within the bound.
    #[must_use]
    pub const fn attempts_remaining(self) -> u32 {
        self.schedule
            .max_query_attempts
            .saturating_sub(self.attempts_consumed)
    }

    /// Returns whether the attempt bound is exhausted.
    ///
    /// An exhausted policy maps the lifecycle to a resumable `Unknown`, never to
    /// a permanent failure.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.attempts_consumed >= self.schedule.max_query_attempts
    }

    /// Returns whether one more query may proceed within the bound.
    #[must_use]
    pub const fn may_query(self) -> bool {
        !self.is_exhausted()
    }

    /// Consumes exactly one attempt and returns whether a query may still
    /// proceed afterwards.
    ///
    /// This is the single mutation. It is called once per
    /// `advance_one_poll` step. If the policy is already exhausted this is a
    /// no-op that returns `false`.
    pub fn consume_one(&mut self) -> bool {
        if self.is_exhausted() {
            return false;
        }
        self.attempts_consumed = self.attempts_consumed.saturating_add(1);
        !self.is_exhausted()
    }
}

impl BackoffSchedule {
    /// Returns the number of permitted attempt indices.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.max_query_attempts
    }

    /// Returns whether the schedule permits no attempts.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.max_query_attempts == 0
    }
}

impl iter::IntoIterator for BackoffSchedule {
    type Item = u32;
    type IntoIter = RangeInclusive<u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.attempt_indices()
    }
}

impl Default for PollingPolicy {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{BackoffSchedule, PollingPolicy};

    #[test]
    fn fresh_policy_has_full_budget() {
        let policy = PollingPolicy::new(5);
        assert_eq!(policy.attempts_consumed(), 0);
        assert_eq!(policy.attempts_remaining(), 5);
        assert!(!policy.is_exhausted());
        assert!(policy.may_query());
        assert_eq!(policy.next_attempt_index(), 1);
    }

    #[test]
    fn consume_one_advances_exactly_one_attempt() {
        let mut policy = PollingPolicy::new(3);
        assert!(policy.consume_one());
        assert_eq!(policy.attempts_consumed(), 1);
        assert_eq!(policy.attempts_remaining(), 2);
        assert!(policy.consume_one());
        assert_eq!(policy.attempts_consumed(), 2);
        assert!(!policy.consume_one());
        assert_eq!(policy.attempts_consumed(), 3);
        assert!(policy.is_exhausted());
        assert!(!policy.may_query());
        // Further consumes are no-ops.
        assert!(!policy.consume_one());
        assert_eq!(policy.attempts_consumed(), 3);
    }

    #[test]
    fn zero_max_is_immediately_exhausted_but_not_failure() {
        let mut policy = PollingPolicy::new(0);
        assert!(policy.is_exhausted());
        assert!(!policy.may_query());
        assert!(!policy.consume_one());
        assert_eq!(policy.attempts_consumed(), 0);
    }

    #[test]
    fn from_consumed_clamps_to_max() {
        let policy = PollingPolicy::from_consumed(4, 7);
        assert_eq!(policy.attempts_consumed(), 4);
        assert!(policy.is_exhausted());
        assert_eq!(policy.attempts_remaining(), 0);
    }

    #[test]
    fn from_consumed_preserves_remaining_budget() {
        let policy = PollingPolicy::from_consumed(5, 2);
        assert_eq!(policy.attempts_consumed(), 2);
        assert_eq!(policy.attempts_remaining(), 3);
        assert!(!policy.is_exhausted());
        assert!(policy.may_query());
    }

    #[test]
    fn schedule_indices_are_one_based_and_contiguous() {
        let schedule = BackoffSchedule::new(4);
        let indices: Vec<u32> = schedule.attempt_indices().collect();
        assert_eq!(indices, vec![1, 2, 3, 4]);
        assert!(schedule.contains(1));
        assert!(schedule.contains(4));
        assert!(!schedule.contains(0));
        assert!(!schedule.contains(5));
    }

    #[test]
    fn policy_is_comparable_and_deterministic() {
        let a = PollingPolicy::from_consumed(5, 2);
        let b = PollingPolicy::from_consumed(5, 2);
        assert_eq!(a, b);
        assert_ne!(a, PollingPolicy::from_consumed(5, 3));
        assert_eq!(a.schedule(), b.schedule());
    }
}
