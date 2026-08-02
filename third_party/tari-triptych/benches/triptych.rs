// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![expect(missing_docs)]

#[macro_use]
extern crate criterion;

use criterion::{BatchSize, Criterion};
use curve25519_dalek::{RistrettoPoint, Scalar};
use itertools::izip;
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use triptych::{
    parameters::TriptychParameters,
    proof::TriptychProof,
    statement::{TriptychInputSet, TriptychStatement},
    witness::TriptychWitness,
    Transcript,
};

// Parameters
const N_VALUES: [u32; 1] = [2];
const M_VALUES: [u32; 4] = [2, 4, 8, 10];
const BATCH_SIZES: [usize; 1] = [2];

// Generate a batch of witnesses, statements, and transcripts
#[expect(non_snake_case)]
#[expect(clippy::arithmetic_side_effects)]
fn generate_data<R: CryptoRngCore>(
    params: &TriptychParameters,
    b: usize,
    rng: &mut R,
) -> (Vec<TriptychWitness>, Vec<TriptychStatement>, Vec<Transcript>) {
    // Generate witnesses; for this test, we use adjacent indexes for simplicity
    // This means the batch size must not exceed the input set size!
    assert!(b <= params.get_N() as usize);
    let mut witnesses = Vec::with_capacity(b);
    witnesses.push(TriptychWitness::random(params, rng));
    for _ in 1..b {
        let r = Scalar::random(rng);
        let l = (witnesses.last().unwrap().get_l() + 1) % params.get_N();
        witnesses.push(TriptychWitness::new(params, l, &r).unwrap());
    }

    // Generate input set from all witnesses
    let mut M = (0..params.get_N())
        .map(|_| RistrettoPoint::random(rng))
        .collect::<Vec<RistrettoPoint>>();
    for witness in &witnesses {
        M[witness.get_l() as usize] = witness.compute_verification_key();
    }
    let input_set = TriptychInputSet::new(&M).unwrap();

    // Generate statements
    let mut statements = Vec::with_capacity(b);
    for witness in &witnesses {
        let J = witness.compute_linking_tag();
        statements.push(TriptychStatement::new(params, &input_set, &J).unwrap());
    }

    // Generate transcripts
    let transcripts = (0..b)
        .map(|i| {
            let mut transcript = Transcript::new(b"Test transcript");
            transcript.append_u64(b"index", i as u64);

            transcript
        })
        .collect::<Vec<Transcript>>();

    (witnesses, statements, transcripts)
}

fn generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = TriptychParameters::new(n, m).unwrap();

            let label = format!("Generate proof: n = {}, m = {} (N = {})", n, m, params.get_N());
            group.bench_function(&label, |b| {
                // Generate data
                let (witnesses, statements, transcripts) = generate_data(&params, 1, &mut rng);

                // Start the benchmark
                b.iter_batched_ref(
                    || transcripts[0].clone(),
                    |t| {
                        // Generate the proof
                        TriptychProof::prove_with_rng(&witnesses[0], &statements[0], &mut rng, t).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn generate_proof_vartime(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof_vartime");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = TriptychParameters::new(n, m).unwrap();

            let label = format!(
                "Generate proof (variable time): n = {}, m = {} (N = {})",
                n,
                m,
                params.get_N()
            );
            group.bench_function(&label, |b| {
                // Generate data
                let (witnesses, statements, transcripts) = generate_data(&params, 1, &mut rng);

                // Start the benchmark
                b.iter_batched_ref(
                    || transcripts[0].clone(),
                    |t| {
                        // Generate the proof
                        TriptychProof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, t).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = TriptychParameters::new(n, m).unwrap();

            let label = format!("Verify proof: n = {}, m = {} (N = {})", n, m, params.get_N());
            group.bench_function(&label, |b| {
                // Generate data
                let (witnesses, statements, transcripts) = generate_data(&params, 1, &mut rng);

                // Generate the proof
                let proof =
                    TriptychProof::prove_with_rng(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone())
                        .unwrap();

                // Start the benchmark
                b.iter_batched_ref(
                    || transcripts[0].clone(),
                    |t| {
                        // Verify the proof
                        assert!(proof.verify(&statements[0], t).is_ok());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn verify_batch_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_batch_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = TriptychParameters::new(n, m).unwrap();

            for batch in BATCH_SIZES {
                let label = format!(
                    "Verify batch proof: n = {}, m = {} (N = {}), {}-batch",
                    n,
                    m,
                    params.get_N(),
                    batch
                );
                group.bench_function(&label, |b| {
                    // Generate data
                    let (witnesses, statements, transcripts) = generate_data(&params, batch, &mut rng);

                    // Generate the proofs
                    let proofs = izip!(witnesses.iter(), statements.iter(), transcripts.clone().iter_mut())
                        .map(|(w, s, t)| TriptychProof::prove_with_rng_vartime(w, s, &mut rng, t).unwrap())
                        .collect::<Vec<TriptychProof>>();

                    // Start the benchmark
                    b.iter_batched_ref(
                        || transcripts.clone(),
                        |t| {
                            // Verify the proofs in a batch
                            assert!(TriptychProof::verify_batch(&statements, &proofs, t).is_ok());
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
        }
    }
    group.finish();
}

criterion_group! {
    name = generate;
    config = Criterion::default();
    targets = generate_proof, generate_proof_vartime
}

criterion_group! {
    name = verify;
    config = Criterion::default();
    targets = verify_proof, verify_batch_proof
}

criterion_main!(generate, verify);
