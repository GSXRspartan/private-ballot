//! Wall-clock backoff tests (Slice 4A10 §16.2).

mod common;

use std::time::Duration;

use tari_cc_private_ballot_ootle_anchor_app::{BackoffError, WallClockBackoff};

#[test]
fn attempt_zero_returns_zero() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(1),
        Duration::from_secs(4),
    ));
    assert_eq!(backoff.delay_for(0), Duration::ZERO);
}

#[test]
fn attempt_one_returns_base() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(1),
        Duration::from_secs(8),
    ));
    assert_eq!(backoff.delay_for(1), Duration::from_secs(1));
}

#[test]
fn exponential_growth_doubles() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(1),
        Duration::from_secs(64),
    ));
    assert_eq!(backoff.delay_for(2), Duration::from_secs(2));
    assert_eq!(backoff.delay_for(3), Duration::from_secs(4));
    assert_eq!(backoff.delay_for(4), Duration::from_secs(8));
}

#[test]
fn cap_saturates() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(1),
        Duration::from_secs(4),
    ));
    assert_eq!(backoff.delay_for(3), Duration::from_secs(4));
    assert_eq!(backoff.delay_for(100), Duration::from_secs(4));
}

#[test]
fn zero_base_rejected() {
    let result = WallClockBackoff::new(Duration::ZERO, Duration::from_secs(4));
    assert_eq!(result, Err(BackoffError::ZeroBase));
}

#[test]
fn cap_below_base_rejected() {
    let result = WallClockBackoff::new(Duration::from_secs(8), Duration::from_secs(4));
    assert_eq!(result, Err(BackoffError::CapBelowBase));
}

#[test]
fn deterministic_across_calls() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(1),
        Duration::from_secs(8),
    ));
    for attempt in 0..6 {
        assert_eq!(backoff.delay_for(attempt), backoff.delay_for(attempt));
    }
}

#[test]
fn base_and_cap_accessors() {
    let backoff = ok(WallClockBackoff::new(
        Duration::from_secs(2),
        Duration::from_secs(16),
    ));
    assert_eq!(backoff.base(), Duration::from_secs(2));
    assert_eq!(backoff.cap(), Duration::from_secs(16));
}

fn ok(result: Result<WallClockBackoff, BackoffError>) -> WallClockBackoff {
    match result {
        Ok(backoff) => backoff,
        Err(error) => panic!("backoff construction failed: {error}"),
    }
}
