// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! In a RingCT design, outputs have (roughly speaking) two parts that we need:
//! - an output verification key, usually derived from a recipient address and nonce
//! - a value commitment, where the mask is derived from a shared secret
//!
//! A linkable ring signature is required in such a design.
//!
//! This example shows how to use Triptych.
#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use merlin::Transcript;
    use rand_core::OsRng;
    use triptych::parallel::*;

    #[expect(non_snake_case)]
    #[test]
    fn ringct() {
        // It's important to use a cryptographically-secure random number generator!
        let mut rng = OsRng;

        // Parameters that will define the number of outputs used in the proof: 2^4 == 16
        let n = 2;
        let m = 4;
        let params = TriptychParameters::new(n, m).unwrap();
        let number_outputs = params.get_N();

        // Value commitments use the Triptych `G` generator for masks, and need another component for values
        // In practice it's essential that `G` and `H` have no efficiently-computable discrete logarithm relationship
        // For this example, we'll just make it random; in the real world, you'd use a verifiable construction
        let H = RistrettoPoint::random(&mut rng);

        // All output verification keys and value commitments (except ours) look random to us, so just make them random!
        let mut output_keys = (0..number_outputs)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<RistrettoPoint>>();
        let mut value_commitments = (0..number_outputs)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<RistrettoPoint>>();

        // We'll put the output we control at some arbitrary index within the sets
        let index: u32 = 7;

        // We know the signing key corresponding to the output verification key
        let signing_key = Scalar::random(&mut rng);
        output_keys[index as usize] = signing_key * params.get_G();

        // We also know the value and mask corresponding to the value commitment
        let commitment_value = Scalar::from(12345u32);
        let commitment_mask = Scalar::random(&mut rng);
        value_commitments[index as usize] = commitment_value * H + commitment_mask * params.get_G1();

        // In RingCT, the linkable ring signature (Triptych, in this case) comes equipped with a commitment offset
        // This is a commitment to the same value, but with a different mask
        // Why? Because the difference between the value commitment and offset now looks like a verification key!
        // (The value components cancel)
        let offset_mask = Scalar::random(&mut rng);
        let offset = commitment_value * H + offset_mask * params.get_G1();

        // We are ready to set up the Triptych witness!
        // This includes the signing key and the difference between the value commitment and offset masks
        let witness = TriptychWitness::new(&params, index, &signing_key, &(commitment_mask - offset_mask)).unwrap();

        // We can also set up the input set and statement
        // The linkable ring signature also comes equipped with a linking tag; the library can compute it for us
        let input_set = TriptychInputSet::new(&output_keys, &value_commitments).unwrap();
        let statement = TriptychStatement::new(&params, &input_set, &offset, &witness.compute_linking_tag()).unwrap();

        // The proof needs a transcript associated to it
        // This binds any important context we might care about
        // For this example, we'll keep it simple
        let mut transcript = Transcript::new(b"An example of RingCT with Triptych");

        // At long last, build the proof!
        // Note that we need to clone the transcript here, since the verifier needs to use the original one
        let proof = TriptychProof::prove_with_rng(&witness, &statement, &mut rng, &mut transcript.clone()).unwrap();

        // The proof should verify
        assert!(proof.verify(&statement, &mut transcript).is_ok());
    }
}
