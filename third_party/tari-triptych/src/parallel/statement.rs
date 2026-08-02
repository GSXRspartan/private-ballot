// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{sync::Arc, vec, vec::Vec};

use curve25519_dalek::{traits::Identity, RistrettoPoint};
use snafu::prelude::*;

use crate::{domains, parallel::TriptychParameters, Transcript};

/// A Triptych input set.
///
/// An input set is constructed from a vector of verification keys and vector of auxiliary verification keys.
/// Internally, it also contains cryptographic hash data to make proofs more efficient.
#[expect(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriptychInputSet {
    M: Arc<Vec<RistrettoPoint>>,
    M1: Arc<Vec<RistrettoPoint>>,
    hash: Vec<u8>,
}

impl TriptychInputSet {
    /// Generate a new [`TriptychInputSet`] from a slice `M` of verification keys and slice `M1` of auxiliary
    /// verification keys.
    #[expect(non_snake_case)]
    pub fn new(M: &[RistrettoPoint], M1: &[RistrettoPoint]) -> Result<Self, StatementError> {
        // The verification key vectors must be the same length
        if M.len() != M1.len() {
            return Err(StatementError::InvalidParameter {
                reason: "`M` and `M1` did not have matching lengths",
            });
        }

        Self::new_internal(M, M1, M.len())
    }

    /// Generate a new padded [`TriptychInputSet`] from a slice `M` of verification keys, a slice `M1` of auxiliary
    /// verification keys, and [`TriptychParameters`] `params`.
    ///
    /// If either the verification key vector or auxiliary verification key vector are shorter than specified by
    /// `params`, they will be padded by repeating the corresponding last element. If your use case cannot safely
    /// allow this, use [`TriptychInputSet::new`] instead.
    ///
    /// If the verification key vector or auxiliary verification key vector are empty or longer than specified by
    /// `params`, returns a [`StatementError`].
    #[expect(non_snake_case)]
    pub fn new_with_padding(
        M: &[RistrettoPoint],
        M1: &[RistrettoPoint],
        params: &TriptychParameters,
    ) -> Result<Self, StatementError> {
        // The vectors must be the same length
        if M.len() != M1.len() {
            return Err(StatementError::InvalidParameter {
                reason: "`M` and `M1` did not have matching lengths",
            });
        }

        // Get the unpadded size
        let unpadded_size = M.len();

        // We cannot have the vectors be too long
        if unpadded_size > params.get_N() as usize {
            return Err(StatementError::InvalidParameter {
                reason: "unpadded size exceeded `N`",
            });
        }

        // Get the last elements, which also ensures the vectors are nonempty
        let last = M.last().ok_or(StatementError::InvalidParameter {
            reason: "`M` was empty",
        })?;
        let last1 = M1.last().ok_or(StatementError::InvalidParameter {
            reason: "`M1` was empty",
        })?;

        // Pad the vectors with the corresponding last elements
        let mut M_padded = M.to_vec();
        M_padded.resize(params.get_N() as usize, *last);
        let mut M1_padded = M1.to_vec();
        M1_padded.resize(params.get_N() as usize, *last1);

        Self::new_internal(&M_padded, &M1_padded, unpadded_size)
    }

    // Helper function to do the actual generation
    #[expect(non_snake_case)]
    fn new_internal(M: &[RistrettoPoint], M1: &[RistrettoPoint], unpadded_size: usize) -> Result<Self, StatementError> {
        // Ensure the verification key vector lengths don't overflow
        let unpadded_size = u32::try_from(unpadded_size).map_err(|_| StatementError::InvalidParameter {
            reason: "unpadded size overflowed `u32`",
        })?;

        // Use Merlin for the transcript hash
        let mut transcript = Transcript::new(domains::TRANSCRIPT_PARALLEL_INPUT_SET.as_bytes());
        transcript.append_u64(b"version", domains::VERSION);
        transcript.append_message(b"unpadded_size", &unpadded_size.to_le_bytes());
        for item in M {
            transcript.append_message(b"M", item.compress().as_bytes());
        }
        for item in M1 {
            transcript.append_message(b"M1", item.compress().as_bytes());
        }
        let mut hash = vec![0u8; domains::TRANSCRIPT_HASH_BYTES];
        transcript.challenge_bytes(b"hash", &mut hash);

        Ok(Self {
            M: Arc::new(M.to_vec()),
            M1: Arc::new(M1.to_vec()),
            hash,
        })
    }

    /// Get the verification keys for this [`TriptychInputSet`].
    pub fn get_keys(&self) -> &[RistrettoPoint] {
        &self.M
    }

    /// Get the auxiliary verification keys for this [`TriptychInputSet`].
    pub fn get_auxiliary_keys(&self) -> &[RistrettoPoint] {
        &self.M1
    }

    /// Get a cryptographic hash representation of this [`TriptychInputSet`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

/// A Triptych proof statement.
///
/// The statement consists of an [`TriptychInputSet`] of verification and auxiliary verification keys, an offset, and a
/// linking tag. It also contains [`TriptychParameters`] that, among other things, enforce the size of the
/// [`TriptychInputSet`].
#[expect(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct TriptychStatement {
    params: TriptychParameters,
    input_set: TriptychInputSet,
    offset: RistrettoPoint,
    J: RistrettoPoint,
    hash: Vec<u8>,
}

/// Errors that can arise relating to [`TriptychStatement`].
#[derive(Debug, Snafu)]
pub enum StatementError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided: {reason}"))]
    InvalidParameter {
        /// The reason for the parameter error.
        reason: &'static str,
    },
}

impl TriptychStatement {
    /// Generate a new [`TriptychStatement`].
    ///
    /// The [`TriptychInputSet`] `input_set` must have a verification key vector whose size matches that specified by
    /// the [`TriptychParameters`] `params`, and which does not contain the identity group element.
    /// If either of these conditions is not met, returns a [`StatementError`].
    ///
    /// The linking tag `J` is assumed to have been computed from
    /// [`TriptychWitness::compute_linking_tag`](`crate::witness::TriptychWitness::compute_linking_tag`) data or
    /// otherwise provided externally.
    #[expect(non_snake_case)]
    pub fn new(
        params: &TriptychParameters,
        input_set: &TriptychInputSet,
        offset: &RistrettoPoint,
        J: &RistrettoPoint,
    ) -> Result<Self, StatementError> {
        // Check that the input vectors are valid against the parameters
        if input_set.get_keys().len() != params.get_N() as usize {
            return Err(StatementError::InvalidParameter {
                reason: "input vector size was not `N`",
            });
        }
        if input_set.get_keys().contains(&RistrettoPoint::identity()) {
            return Err(StatementError::InvalidParameter {
                reason: "input vector contained the identity point",
            });
        }
        if input_set
            .get_auxiliary_keys()
            .iter()
            .map(|p| p - offset)
            .collect::<Vec<RistrettoPoint>>()
            .contains(&RistrettoPoint::identity())
        {
            return Err(StatementError::InvalidParameter {
                reason: "input vector contained the identity point",
            });
        }

        // Use Merlin for the transcript hash
        let mut transcript = Transcript::new(domains::TRANSCRIPT_PARALLEL_STATEMENT.as_bytes());
        transcript.append_u64(b"version", domains::VERSION);
        transcript.append_message(b"params", params.get_hash());
        transcript.append_message(b"input_set", input_set.get_hash());
        transcript.append_message(b"offset", offset.compress().as_bytes());
        transcript.append_message(b"J", J.compress().as_bytes());
        let mut hash = vec![0u8; domains::TRANSCRIPT_HASH_BYTES];
        transcript.challenge_bytes(b"hash", &mut hash);

        Ok(Self {
            params: params.clone(),
            input_set: input_set.clone(),
            offset: *offset,
            J: *J,
            hash,
        })
    }

    /// Get the parameters for this [`TriptychStatement`].
    pub fn get_params(&self) -> &TriptychParameters {
        &self.params
    }

    /// Get the input set for this [`TriptychStatement`].
    pub fn get_input_set(&self) -> &TriptychInputSet {
        &self.input_set
    }

    /// Get the offset for this [`TriptychStatement`].
    pub fn get_offset(&self) -> &RistrettoPoint {
        &self.offset
    }

    /// Get the linking tag for this [`TriptychStatement`].
    #[expect(non_snake_case)]
    pub fn get_J(&self) -> &RistrettoPoint {
        &self.J
    }

    /// Get a cryptographic hash representation of this [`TriptychStatement`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

#[cfg(test)]
mod test {
    use alloc::{borrow::ToOwned, vec::Vec};

    use curve25519_dalek::RistrettoPoint;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::parallel::{TriptychInputSet, TriptychParameters};

    // Helper function to generate random vectors
    fn random_vector(size: usize) -> Vec<RistrettoPoint> {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);

        (0..size)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<RistrettoPoint>>()
    }

    #[test]
    #[expect(non_snake_case)]
    fn test_padding() {
        // Generate parameters
        let params = TriptychParameters::new(2, 4).unwrap();
        let N = params.get_N() as usize;

        // Vectors are empty
        assert!(TriptychInputSet::new_with_padding(&[], &[], &params).is_err());

        // Vectors are too long
        let M = random_vector(N + 1);
        let M1 = random_vector(N + 1);
        assert!(TriptychInputSet::new_with_padding(&M, &M1, &params).is_err());

        // Vectors are the right size
        let M = random_vector(N);
        let M1 = random_vector(N);
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &M1, &params).unwrap(),
            TriptychInputSet::new(&M, &M1).unwrap()
        );

        // Vectors are padded
        let M = random_vector(N - 1);
        let mut M_padded = M.clone();
        M_padded.push(M.last().unwrap().to_owned());
        let M1 = random_vector(N - 1);
        let mut M1_padded = M1.clone();
        M1_padded.push(M1.last().unwrap().to_owned());
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &M1, &params).unwrap().get_keys(),
            TriptychInputSet::new(&M_padded, &M1_padded).unwrap().get_keys()
        );
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &M1, &params)
                .unwrap()
                .get_auxiliary_keys(),
            TriptychInputSet::new(&M_padded, &M1_padded)
                .unwrap()
                .get_auxiliary_keys()
        );
        assert_ne!(
            TriptychInputSet::new_with_padding(&M, &M1, &params).unwrap().get_hash(),
            TriptychInputSet::new(&M_padded, &M1_padded).unwrap().get_hash()
        )
    }
}
