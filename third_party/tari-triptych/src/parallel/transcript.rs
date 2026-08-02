// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;

use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::TranscriptRng;
use rand_core::CryptoRngCore;

use crate::{
    domains,
    parallel::{proof::ProofError, TriptychParameters, TriptychStatement, TriptychWitness},
    Transcript,
};

/// A Triptych proof transcript.
pub(crate) struct ProofTranscript<'a, R: CryptoRngCore> {
    transcript: &'a mut Transcript,
    witness: Option<&'a TriptychWitness>,
    transcript_rng: TranscriptRng,
    external_rng: &'a mut R,
}

impl<'a, R: CryptoRngCore> ProofTranscript<'a, R> {
    /// Initialize a transcript.
    pub(crate) fn new(
        transcript: &'a mut Transcript,
        statement: &TriptychStatement,
        external_rng: &'a mut R,
        witness: Option<&'a TriptychWitness>,
    ) -> Self {
        // Update the transcript
        transcript.append_message(b"dom-sep", domains::TRANSCRIPT_PARALLEL_PROOF.as_bytes());
        transcript.append_u64(b"version", domains::VERSION);
        transcript.append_message(b"statement", statement.get_hash());

        // Set up the transcript generator
        let transcript_rng = Self::build_transcript_rng(transcript, witness, external_rng);

        Self {
            transcript,
            witness,
            transcript_rng,
            external_rng,
        }
    }

    /// Run the Fiat-Shamir commitment phase and produce challenge powers
    #[expect(non_snake_case, clippy::too_many_arguments)]
    pub(crate) fn commit(
        &mut self,
        params: &TriptychParameters,
        A: &RistrettoPoint,
        B: &RistrettoPoint,
        C: &RistrettoPoint,
        D: &RistrettoPoint,
        X: &Vec<RistrettoPoint>,
        X1: &Vec<RistrettoPoint>,
        Y: &Vec<RistrettoPoint>,
    ) -> Result<Vec<Scalar>, ProofError> {
        let m = params.get_m() as usize;

        // Update the transcript
        self.transcript.append_message(b"A", A.compress().as_bytes());
        self.transcript.append_message(b"B", B.compress().as_bytes());
        self.transcript.append_message(b"C", C.compress().as_bytes());
        self.transcript.append_message(b"D", D.compress().as_bytes());
        for X_item in X {
            self.transcript.append_message(b"X", X_item.compress().as_bytes());
        }
        for X1_item in X1 {
            self.transcript.append_message(b"X1", X1_item.compress().as_bytes());
        }
        for Y_item in Y {
            self.transcript.append_message(b"Y", Y_item.compress().as_bytes());
        }

        // Update the transcript generator
        self.transcript_rng = Self::build_transcript_rng(self.transcript, self.witness, self.external_rng);

        // Get the initial challenge using wide reduction
        let mut xi_bytes = [0u8; 64];
        self.transcript.challenge_bytes(b"xi", &mut xi_bytes);
        let xi = Scalar::from_bytes_mod_order_wide(&xi_bytes);

        // Get powers of the challenge and confirm they are nonzero
        let mut xi_powers = Vec::with_capacity(m.checked_add(1).ok_or(ProofError::InvalidParameter {
            reason: "challenge power count overflowed `usize`",
        })?);
        let mut xi_power = Scalar::ONE;
        for _ in 0..=m {
            if xi_power == Scalar::ZERO {
                return Err(ProofError::InvalidChallenge);
            }

            xi_powers.push(xi_power);
            xi_power *= xi;
        }

        Ok(xi_powers)
    }

    /// Run the Fiat-Shamir response phase
    #[expect(non_snake_case)]
    pub(crate) fn response(
        mut self,
        f: &Vec<Vec<Scalar>>,
        z_A: &Scalar,
        z_C: &Scalar,
        z: &Scalar,
        z1: &Scalar,
    ) -> TranscriptRng {
        // Update the transcript
        for f_row in f {
            for f in f_row {
                self.transcript.append_message(b"f", f.as_bytes());
            }
        }
        self.transcript.append_message(b"z_A", z_A.as_bytes());
        self.transcript.append_message(b"z_C", z_C.as_bytes());
        self.transcript.append_message(b"z", z.as_bytes());
        self.transcript.append_message(b"z1", z1.as_bytes());

        // Update the transcript generator
        self.transcript_rng = Self::build_transcript_rng(self.transcript, self.witness, self.external_rng);

        self.transcript_rng
    }

    /// Get a mutable reference to the transcript generator
    pub(crate) fn as_mut_rng(&mut self) -> &mut TranscriptRng {
        &mut self.transcript_rng
    }

    /// Build a random number generator from a transcript, optionally binding in witness data.
    fn build_transcript_rng(
        transcript: &Transcript,
        witness: Option<&TriptychWitness>,
        external_rng: &mut R,
    ) -> TranscriptRng {
        if let Some(witness) = witness {
            transcript
                .build_rng()
                .rekey_with_witness_bytes(b"l", &witness.get_l().to_le_bytes())
                .rekey_with_witness_bytes(b"r", witness.get_r().as_bytes())
                .rekey_with_witness_bytes(b"r1", witness.get_r1().as_bytes())
                .finalize(external_rng)
        } else {
            transcript.build_rng().finalize(external_rng)
        }
    }
}
