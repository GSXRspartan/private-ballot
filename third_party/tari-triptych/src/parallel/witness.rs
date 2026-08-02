// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::CryptoRngCore;
use snafu::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::parallel::TriptychParameters;

/// A Triptych proof witness.
///
/// The witness consists of a signing key, an auxiliary key, and an index where the corresponding verification and
/// auxiliary verification keys will appear in  the [`TriptychInputSet`](`crate::statement::TriptychInputSet`) of a
/// [`TriptychStatement`](`crate::statement::TriptychStatement`). It also contains [`TriptychParameters`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TriptychWitness {
    #[zeroize(skip)]
    params: TriptychParameters,
    l: u32,
    r: Scalar,
    r1: Scalar,
}

/// Errors that can arise relating to [`TriptychWitness`].
#[derive(Debug, Snafu)]
pub enum WitnessError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided: {reason}"))]
    InvalidParameter {
        /// The reason for the parameter error.
        reason: &'static str,
    },
}

impl TriptychWitness {
    /// Generate a new [`TriptychWitness`] from secret data.
    ///
    /// The signing key `r` and auxiliary key `r1` must be nonzero, and the index `l` must be valid for the
    /// [`TriptychParameters`] `params`. If any of these conditions is not met, returns a [`WitnessError`].
    ///
    /// If you'd like a [`TriptychWitness`] generated securely for you, use [`TriptychWitness::random`] instead.
    pub fn new(params: &TriptychParameters, l: u32, r: &Scalar, r1: &Scalar) -> Result<Self, WitnessError> {
        if r == &Scalar::ZERO {
            return Err(WitnessError::InvalidParameter { reason: "`r == 0`" });
        }
        if r1 == &Scalar::ZERO {
            return Err(WitnessError::InvalidParameter { reason: "`r1 == 0`" });
        }
        if l >= params.get_N() {
            return Err(WitnessError::InvalidParameter { reason: "`l >= N`" });
        }

        Ok(Self {
            params: params.clone(),
            l,
            r: *r,
            r1: *r1,
        })
    }

    /// Generate a new random [`TriptychWitness`].
    ///
    /// You must provide [`TriptychParameters`] `params` and a [`CryptoRngCore`] random number generator `rng`.
    /// This will generate a [`TriptychWitness`] with a cryptographically-secure signing key and random index.
    ///
    /// If you'd rather provide your own secret data, use [`TriptychWitness::new`] instead.
    #[expect(clippy::cast_possible_truncation)]
    pub fn random<R: CryptoRngCore>(params: &TriptychParameters, rng: &mut R) -> Self {
        // Generate a random index using wide reduction
        // This can't truncate since `N` is bounded by `u32`
        // It is also defined since `N > 0`
        #[expect(clippy::arithmetic_side_effects)]
        let l = (rng.as_rngcore().next_u64() % u64::from(params.get_N())) as u32;

        Self {
            params: params.clone(),
            l,
            r: Scalar::random(rng),
            r1: Scalar::random(rng),
        }
    }

    /// Get the [`TriptychParameters`] from this [`TriptychWitness`].
    pub fn get_params(&self) -> &TriptychParameters {
        &self.params
    }

    /// Get the index from this [`TriptychWitness`].
    pub fn get_l(&self) -> u32 {
        self.l
    }

    /// Get the signing key from this [`TriptychWitness`].
    pub fn get_r(&self) -> &Scalar {
        &self.r
    }

    /// Get the auxiliary key from this [`TriptychWitness`].
    pub fn get_r1(&self) -> &Scalar {
        &self.r1
    }

    /// Compute the linking tag for the [`TriptychWitness`] signing key.
    pub fn compute_linking_tag(&self) -> RistrettoPoint {
        *Zeroizing::new(self.r.invert()) * self.params.get_U()
    }

    /// Compute the verification key for the [`TriptychWitness`] signing key.
    pub fn compute_verification_key(&self) -> RistrettoPoint {
        self.r * self.params.get_G()
    }

    /// Compute the auxiliary verification key for the [`TriptychWitness`] signing key.
    pub fn compute_auxiliary_verification_key(&self) -> RistrettoPoint {
        self.r1 * self.params.get_G1()
    }
}
