//! Bounded, deterministic, wall-clock backoff that maps the Slice 4A8 abstract
//! polling-attempt index to a concrete [`std::time::Duration`].
//!
//! The lifecycle orchestrator and its polling policy remain wall-clock-free;
//! this module is the *only* place in the workspace that turns an attempt
//! index into a real `Duration`. The driver then sleeps via
//! [`std::thread::sleep`] between receipt polls. The mapping is:
//!
//! ```text
//! delay_for(0) = Duration::ZERO
//! delay_for(1) = base
//! delay_for(i) = min(cap, base * 2^(i-1))   for i >= 1
//! ```
//!
//! It is deterministic (no randomness, no jitter), bounded by `cap`, and uses
//! saturating arithmetic so it can never overflow or sleep past `cap`.

/// Rejection categories for constructing a [`WallClockBackoff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackoffError {
    /// The base delay was zero.
    ZeroBase,
    /// The cap was below the base delay.
    CapBelowBase,
}

impl BackoffError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroBase => "BACKOFF_ZERO_BASE",
            Self::CapBelowBase => "BACKOFF_CAP_BELOW_BASE",
        }
    }
}

impl core::fmt::Display for BackoffError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for BackoffError {}

/// Deterministic exponential backoff bounded by `cap`.
///
/// Construct with [`WallClockBackoff::new`]; query the delay for a given
/// 1-based attempt index with [`WallClockBackoff::delay_for`]. The driver
/// never sleeps before the first attempt, after a terminal state, or after
/// polling-policy exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClockBackoff {
    base: std::time::Duration,
    cap: std::time::Duration,
}

impl WallClockBackoff {
    /// Builds a backoff schedule from a non-zero `base` and a `cap` that is at
    /// least as large as `base`.
    ///
    /// # Errors
    ///
    /// Returns [`BackoffError::ZeroBase`] if `base` is zero, or
    /// [`BackoffError::CapBelowBase`] if `cap` is below `base`.
    pub const fn new(
        base: std::time::Duration,
        cap: std::time::Duration,
    ) -> Result<Self, BackoffError> {
        if base.is_zero() {
            return Err(BackoffError::ZeroBase);
        }
        let cap_below_base = cap.as_secs() < base.as_secs()
            || (cap.as_secs() == base.as_secs() && cap.subsec_nanos() < base.subsec_nanos());
        if cap_below_base {
            return Err(BackoffError::CapBelowBase);
        }
        Ok(Self { base, cap })
    }

    /// Returns the delay to apply before the given 1-based attempt index.
    ///
    /// `delay_for(0)` returns [`std::time::Duration::ZERO`]; `delay_for(1)`
    /// returns `base`; higher indices return `min(cap, base * 2^(i-1))` with
    /// saturating arithmetic so the result never overflows and never exceeds
    /// `cap`.
    #[must_use]
    pub fn delay_for(&self, attempt_index: u32) -> std::time::Duration {
        if attempt_index == 0 {
            return std::time::Duration::ZERO;
        }
        // Compute base * 2^(attempt_index-1) by repeated saturating doublings.
        // A non-zero base (the only kind `new` accepts) reaches Duration::MAX
        // in at most 64 doublings, so cap the loop there; the final `min`
        // collapses to `cap` whenever the mathematical result exceeds it.
        let mut product = self.base;
        let doublings = attempt_index.saturating_sub(1).min(64);
        for _ in 0..doublings {
            if product >= self.cap {
                return self.cap;
            }
            product = product.saturating_add(product);
        }
        std::cmp::min(product, self.cap)
    }

    /// Returns the configured base delay.
    #[must_use]
    pub const fn base(&self) -> std::time::Duration {
        self.base
    }

    /// Returns the configured cap delay.
    #[must_use]
    pub const fn cap(&self) -> std::time::Duration {
        self.cap
    }
}
