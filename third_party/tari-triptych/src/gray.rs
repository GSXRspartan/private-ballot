// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{vec, vec::Vec};
use core::num::NonZeroU32;

use crypto_bigint::{NonZero, U64};

/// An iterator for arbitrary-base Gray codes.
#[expect(non_snake_case)]
pub(crate) struct GrayIterator {
    N: u32, // base
    M: u32, // number of digits
    // state information
    i: u32,
    last: Vec<u32>,
}

impl GrayIterator {
    /// Generate a new Gray iterator.
    ///
    /// You must provide a base `N > 1` and number of digits `M > 0` such that `N**M` does not overflow `u32`.
    /// If any of these conditions is not met, returns `None`.
    ///
    /// Operations using this iterator run in variable time, so don't use this for secret data.
    /// If you need to get the Gray code decomposition for a secret value, use `decompose` directly.
    #[expect(non_snake_case)]
    pub(crate) fn new(N: u32, M: u32) -> Option<Self> {
        // Check inputs
        if N <= 1 || M == 0 {
            return None;
        }
        N.checked_pow(M)?;

        Some(Self {
            N,
            M,
            i: 0,
            last: vec![0; M as usize],
        })
    }

    /// Get a specific Gray code decomposition, ignoring constant-time operations.
    ///
    /// You must provide a valid value `v` based on the supplied parameters `N` and `M`.
    /// If anything goes wrong, returns `None`.
    /// Otherwise, returns the Gray code as a `u32` digit vector.
    #[expect(non_snake_case)]
    pub(crate) fn decompose_vartime(N: u32, M: u32, mut v: u32) -> Option<Vec<u32>> {
        if N <= 1 || M == 0 {
            return None;
        }

        // Get a base-`N` decomposition
        let mut base_N = Vec::with_capacity(M as usize);
        for _ in 0..M {
            // These are always defined since `N > 0`
            base_N.push(v.checked_rem(N)?);
            v = v.checked_div(N)?;
        }

        // Now get the Gray decomposition from the base-`N` decomposition
        let mut shift = 0;
        let mut digits = vec![0; M as usize];

        for i in (0..M).rev() {
            digits[i as usize] = (base_N[i as usize].checked_add(shift)?).checked_rem(N)?;
            shift = shift.checked_add(N)?.checked_sub(digits[i as usize])?;
        }

        Some(digits)
    }

    /// Get a specific Gray code decomposition, attempting to do so in constant time.
    ///
    /// You must provide a valid value `v` based on the supplied parameters `N` and `M`.
    /// If anything goes wrong, returns `None`.
    /// Otherwise, returns the Gray code as a `u32` digit vector.
    #[expect(non_snake_case)]
    pub(crate) fn decompose(N: u32, M: u32, v: u32) -> Option<Vec<u32>> {
        if N <= 1 || M == 0 {
            return None;
        }

        // Convert to constant-time-friendly `U64`
        let mut v_U64 = U64::from_u32(v);
        let N_nonzero = NonZero::<U64>::from_u32(NonZeroU32::new(N)?);

        // Get a base-`N` decomposition in constant time
        let mut base_N = Vec::with_capacity(M as usize);
        for _ in 0..M {
            let (q, r) = v_U64.div_rem(&N_nonzero);

            base_N.push(r);
            v_U64 = q;
        }

        // Now get the Gray decomposition from the base-`N` decomposition
        let mut shift = U64::ZERO;
        let mut digits = vec![U64::ZERO; M as usize];

        for i in (0..M).rev() {
            digits[i as usize] = base_N[i as usize].saturating_add(&shift).rem(&N_nonzero);
            shift = shift.saturating_add(&N_nonzero).saturating_sub(&digits[i as usize]);
        }

        // Get the digits as `u32`
        digits
            .iter()
            .map(|d| u32::try_from(u64::from(*d)).ok())
            .collect::<Option<Vec<u32>>>()
    }
}

impl Iterator for GrayIterator {
    type Item = (usize, u32, u32);

    /// Return data on Gray code changes.
    ///
    /// This actually a returns a tuple `(index, old, new)`:
    /// - `index` is the digit vector index that has changed
    /// - `old` is its previous value
    /// - `new` is its new value
    ///
    /// The first iteration is a special case that always returns `(0, 0, 0)`.
    ///
    /// Keep in mind that this does not return the actual Gray code!
    /// You must keep track of that yourself.
    fn next(&mut self) -> Option<Self::Item> {
        if self.i == 0 {
            self.i = 1;
            return Some((0, 0, 0));
        }

        // We have iterated over all codes
        if self.i == self.N.checked_pow(self.M)? {
            return None;
        }

        // Decompose the index
        let next = Self::decompose_vartime(self.N, self.M, self.i)?;

        // Locate the changed digit
        let index = self
            .last
            .iter()
            .zip(next.iter())
            .position(|(last, next)| last != next)?;
        let old = self.last[index];
        let new = next[index];

        // Update the state
        self.i = self.i.checked_add(1)?;
        self.last = next;

        Some((index, old, new))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[expect(non_snake_case)]
    fn test_gray_iterator() {
        // Set up parameters
        let N = 3u32;
        let K = 2u32;

        // Keep track of all digit vectors we've seen, since none should repeat
        let mut digits_seen = Vec::new();

        // Keep track of the digit vector
        let mut digits = vec![0; K as usize];

        for (i, (index, old, new)) in GrayIterator::new(N, K).unwrap().enumerate() {
            // Ensure the old value is correct
            assert_eq!(digits[index], old);

            // Update the code according to the change data
            digits[index] = new;

            // Check against the value getter
            assert_eq!(
                digits,
                GrayIterator::decompose(N, K, u32::try_from(i).unwrap()).unwrap()
            );

            // Make sure we haven't seen this decomposition before
            assert!(!digits_seen.contains(&digits));
            digits_seen.push(digits.clone());
        }
    }

    #[test]
    #[expect(non_snake_case)]
    fn test_gray_iterator_vartime() {
        // Set up parameters
        let N = 3u32;
        let K = 2u32;

        // Keep track of all digit vectors we've seen, since none should repeat
        let mut digits_seen = Vec::new();

        // Keep track of the digit vector
        let mut digits = vec![0; K as usize];

        for (i, (index, old, new)) in GrayIterator::new(N, K).unwrap().enumerate() {
            // Ensure the old value is correct
            assert_eq!(digits[index], old);

            // Update the code according to the change data
            digits[index] = new;

            // Check against the value getter
            assert_eq!(
                digits,
                GrayIterator::decompose_vartime(N, K, u32::try_from(i).unwrap()).unwrap()
            );

            // Make sure we haven't seen this decomposition before
            assert!(!digits_seen.contains(&digits));
            digits_seen.push(digits.clone());
        }
    }
}
