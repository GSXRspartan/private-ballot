// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{sync::Arc, vec, vec::Vec};
use core::iter::once;

use blake3::Hasher;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    traits::{MultiscalarMul, VartimeMultiscalarMul},
    RistrettoPoint,
    Scalar,
};
use snafu::prelude::*;

use crate::{domains, util::OperationTiming, Transcript};

/// Public parameters used for generating and verifying Triptych proofs.
///
/// Parameters require a base and exponent that define the size of verification key vectors, as well as group generators
/// `G`, `G1`, and `U` required by the protocol. You can either use [`TriptychParameters::new`] to have these generators
/// defined securely for you, or use [`TriptychParameters::new_with_generators`] if your use case requires specific
/// values for these.
#[expect(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct TriptychParameters {
    n: u32,
    m: u32,
    G: RistrettoPoint,
    G1: RistrettoPoint,
    U: RistrettoPoint,
    CommitmentG: Arc<Vec<RistrettoPoint>>,
    CommitmentH: RistrettoPoint,
    hash: Vec<u8>,
}

/// Errors that can arise relating to [`TriptychParameters`].
#[derive(Debug, Snafu)]
pub enum ParameterError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided: {reason}"))]
    InvalidParameter {
        /// The reason for the parameter error.
        reason: &'static str,
    },
}

impl TriptychParameters {
    /// Generate new [`TriptychParameters`] for Triptych proofs.
    ///
    /// The base `n > 1` and exponent `m > 1` define the size of verification key vectors, so it must be the case that
    /// `n**m` does not overflow [`prim@u32`]. If any of these conditions is not met, returns a [`ParameterError`].
    ///
    /// This function produces group generators `G`, `G1` and `U` for you.
    /// If your use case requires specific generators, use [`TriptychParameters::new_with_generators`] instead.
    #[expect(non_snake_case)]
    pub fn new(n: u32, m: u32) -> Result<Self, ParameterError> {
        // Use the default base point for `G` (this is arbitrary)
        let G = RISTRETTO_BASEPOINT_POINT;

        // Use `BLAKE3` to generate `G1`
        let mut G1_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(domains::POINT_G1.as_bytes());
        hasher.update(&domains::VERSION.to_le_bytes());
        hasher.finalize_xof().fill(&mut G1_bytes);
        let G1 = RistrettoPoint::from_uniform_bytes(&G1_bytes);

        // Use `BLAKE3` to generate `U`
        let mut U_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(domains::POINT_U.as_bytes());
        hasher.update(&domains::VERSION.to_le_bytes());
        hasher.finalize_xof().fill(&mut U_bytes);
        let U = RistrettoPoint::from_uniform_bytes(&U_bytes);

        Self::new_with_generators(n, m, &G, &G1, &U)
    }

    /// Generate new [`TriptychParameters`] for Triptych proofs.
    ///
    /// The base `n > 1` and exponent `m > 1` define the size of verification key vectors, so it must be the case that
    /// `n**m` does not overflow [`prim@u32`]. If any of these conditions is not met, returns a [`ParameterError`].
    ///
    /// You must also provide independent group generators `G`, `G1` and `U`:
    /// - The generator `G` is used to define verification keys.
    /// - The generator `G1` is used to define auxiliary verification keys.
    /// - The generator `U` is used to define linking tags.
    ///
    /// The security of these generators cannot be checked by this function.
    /// If you'd rather have the generators securely defined for you, use [`TriptychParameters::new`] instead.
    #[expect(non_snake_case)]
    pub fn new_with_generators(
        n: u32,
        m: u32,
        G: &RistrettoPoint,
        G1: &RistrettoPoint,
        U: &RistrettoPoint,
    ) -> Result<Self, ParameterError> {
        // These bounds are required by the protocol
        if n < 2 {
            return Err(ParameterError::InvalidParameter { reason: "`n < 2`" });
        }
        if m < 2 {
            return Err(ParameterError::InvalidParameter { reason: "`m < 2`" });
        }

        // Check that the parameters don't overflow `u32`
        if n.checked_pow(m).is_none() {
            return Err(ParameterError::InvalidParameter {
                reason: "`n**m` overflowed `u32`",
            });
        }

        // Use `BLAKE3` to generate `CommitmentH`
        let mut CommitmentH_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(domains::POINT_COMMITMENT_H.as_bytes());
        hasher.update(&domains::VERSION.to_le_bytes());
        hasher.finalize_xof().fill(&mut CommitmentH_bytes);
        let CommitmentH = RistrettoPoint::from_uniform_bytes(&CommitmentH_bytes);

        // Use `BLAKE3` for the commitment matrix generators
        let mut hasher = Hasher::new();
        hasher.update(domains::POINT_COMMITMENT_G.as_bytes());
        hasher.update(&domains::VERSION.to_le_bytes());
        hasher.update(&n.to_le_bytes());
        hasher.update(&m.to_le_bytes());
        let mut hasher_xof = hasher.finalize_xof();
        let mut CommitmentG_bytes = [0u8; 64];
        let CommitmentG = (0..n.checked_mul(m).ok_or(ParameterError::InvalidParameter {
            reason: "`n*m` overflowed `u32`",
        })?)
            .map(|_| {
                hasher_xof.fill(&mut CommitmentG_bytes);
                RistrettoPoint::from_uniform_bytes(&CommitmentG_bytes)
            })
            .collect::<Vec<RistrettoPoint>>();

        // Use Merlin for the transcript hash
        let mut transcript = Transcript::new(domains::TRANSCRIPT_PARALLEL_PARAMETERS.as_bytes());
        transcript.append_u64(b"version", domains::VERSION);
        transcript.append_message(b"n", &n.to_le_bytes());
        transcript.append_message(b"m", &m.to_le_bytes());
        transcript.append_message(b"G", G.compress().as_bytes());
        transcript.append_message(b"G1", G1.compress().as_bytes());
        transcript.append_message(b"U", U.compress().as_bytes());
        for item in &CommitmentG {
            transcript.append_message(b"CommitmentG", item.compress().as_bytes());
        }
        transcript.append_message(b"CommitmentH", CommitmentH.compress().as_bytes());
        let mut hash = vec![0u8; domains::TRANSCRIPT_HASH_BYTES];
        transcript.challenge_bytes(b"hash", &mut hash);

        Ok(TriptychParameters {
            n,
            m,
            G: *G,
            G1: *G1,
            U: *U,
            CommitmentG: Arc::new(CommitmentG),
            CommitmentH,
            hash,
        })
    }

    /// Commit to a matrix.
    ///
    /// This requires that `matrix` be an `m x n` scalar matrix.
    /// You can decide if you want to use variable-time operations via the `vartime` flag.
    pub(crate) fn commit_matrix(
        &self,
        matrix: &[Vec<Scalar>],
        mask: &Scalar,
        timing: OperationTiming,
    ) -> Result<RistrettoPoint, ParameterError> {
        // Check that the matrix dimensions are valid
        if matrix.len() != (self.m as usize) {
            return Err(ParameterError::InvalidParameter {
                reason: "matrix did not have `m` rows",
            });
        }
        if matrix.iter().any(|m| m.len() != (self.n as usize)) {
            return Err(ParameterError::InvalidParameter {
                reason: "matrix did not have `n` columns",
            });
        }

        // Flatten before evaluating the commitment
        let scalars = matrix.iter().flatten().chain(once(mask)).collect::<Vec<&Scalar>>();
        let points = self.get_CommitmentG().iter().chain(once(self.get_CommitmentH()));

        match timing {
            OperationTiming::Constant => Ok(RistrettoPoint::multiscalar_mul(scalars, points)),
            OperationTiming::Variable => Ok(RistrettoPoint::vartime_multiscalar_mul(scalars, points)),
        }
    }

    /// Get the group generator `G` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining verification keys.
    #[expect(non_snake_case)]
    pub fn get_G(&self) -> &RistrettoPoint {
        &self.G
    }

    /// Get the group generator `G1` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining auxiliary verification keys.
    #[expect(non_snake_case)]
    pub fn get_G1(&self) -> &RistrettoPoint {
        &self.G1
    }

    /// Get the group generator `U` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining linking tags.
    #[expect(non_snake_case)]
    pub fn get_U(&self) -> &RistrettoPoint {
        &self.U
    }

    /// Get the value `n` from these [`TriptychParameters`].
    ///
    /// This is the base used for defining the verification key vector size.
    pub fn get_n(&self) -> u32 {
        self.n
    }

    /// Get the value `m` from these [`TriptychParameters`].
    ///
    /// This is the exponent used for defining the verification key vector size.
    pub fn get_m(&self) -> u32 {
        self.m
    }

    /// Get the value `N == n**m` from these [`TriptychParameters`].
    ///
    /// This is the verification key vector size.
    #[expect(non_snake_case)]
    pub fn get_N(&self) -> u32 {
        // This is guaranteed not to overflow
        self.n.pow(self.m)
    }

    /// Get the value `CommitmentG` from these [`TriptychParameters`].
    #[expect(non_snake_case)]
    pub(crate) fn get_CommitmentG(&self) -> &Vec<RistrettoPoint> {
        &self.CommitmentG
    }

    /// Get the value `CommitmentH` from these [`TriptychParameters`].
    #[expect(non_snake_case)]
    pub(crate) fn get_CommitmentH(&self) -> &RistrettoPoint {
        &self.CommitmentH
    }

    /// Get a cryptographic hash representation of these [`TriptychParameters`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}
