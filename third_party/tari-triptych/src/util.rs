// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::Scalar;
use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng,
    RngCore,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Options for constant- or variable-time operations.
#[derive(Clone, Copy)]
pub(crate) enum OperationTiming {
    /// The operation should attempt to run in constant time
    Constant,
    /// The operation may run in variable time
    Variable,
}

/// Kronecker delta function with scalar output, possibly in constant time.
pub(crate) fn delta(x: u32, y: u32, timing: OperationTiming) -> Scalar {
    match timing {
        OperationTiming::Constant => {
            let mut result = Scalar::ZERO;
            result.conditional_assign(&Scalar::ONE, x.ct_eq(&y));
            result
        },
        OperationTiming::Variable => {
            if x == y {
                Scalar::ONE
            } else {
                Scalar::ZERO
            }
        },
    }
}

/// A null random number generator that exists only for deterministic transcript-based weight generation.
/// It only produces zero.
/// This is DANGEROUS in general, and you almost certainly should not use it elsewhere!
pub(crate) struct NullRng;

impl RngCore for NullRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.zeroize();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }
}

// This isn't really cryptographically secure!
// We only do this so `NullRng` can be used with `TranscriptRng` due to a trait bound.
impl CryptoRng for NullRng {}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;
    use rand_core::RngCore;

    use super::{NullRng, OperationTiming};
    use crate::util::delta;

    #[test]
    fn test_delta() {
        for timing in [OperationTiming::Constant, OperationTiming::Variable] {
            // Equal values
            assert_eq!(delta(0, 0, timing), Scalar::ONE);
            assert_eq!(delta(1, 1, timing), Scalar::ONE);
            assert_eq!(delta(u32::MAX, u32::MAX, timing), Scalar::ONE);

            // Unequal values
            assert_eq!(delta(0, 1, timing), Scalar::ZERO);
            assert_eq!(delta(1, 0, timing), Scalar::ZERO);
            assert_eq!(delta(u32::MAX, 0, timing), Scalar::ZERO);
        }
    }

    #[test]
    fn test_null_rng() {
        // Ensure that the null RNG supplies only zero
        let mut rng = NullRng;

        assert_eq!(rng.next_u32(), 0);
        assert_eq!(rng.next_u64(), 0);

        // Ensure that buffers are filled with only zero
        const BUFFER_SIZE: usize = 128;

        let mut buffer = [1u8; BUFFER_SIZE]; // start with nonzero
        rng.fill_bytes(&mut buffer);
        assert_eq!(buffer, [0u8; BUFFER_SIZE]);

        let mut buffer = [1u8; BUFFER_SIZE]; // start with nonzero
        rng.try_fill_bytes(&mut buffer).unwrap();
        assert_eq!(buffer, [0u8; BUFFER_SIZE]);
    }
}
