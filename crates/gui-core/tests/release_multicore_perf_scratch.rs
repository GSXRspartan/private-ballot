//! SCRATCH release multicore reconstruction benchmark (Production Release Audit).
//!
//! Disposable: reproduces the Slice 4B §21 bounded-multicore measurement on the
//! REAL production executor (`from_durable_snapshot_parallel`) under --release,
//! to confirm worker scaling holds after optimization. Archived into
//! PRODUCTION_RELEASE_CRYPTO_PERFORMANCE_AUDIT.md/.csv, then removed. Touches no
//! production source, durable format, protocol, or vendored crypto. Ignored by
//! default.
//!
//!   cargo +1.97.1-x86_64-pc-windows-msvc test -p tari-cc-private-ballot-gui-core \
//!     --release --test release_multicore_perf_scratch -- --ignored --nocapture

mod common;

use std::time::Instant;

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionSnapshotV1, GuiElectionSessionV1, HistoricalReplayConfigV1,
    global_crypto_worker_budget_v1,
};

use common::{open_session, triptych_package_bytes};

const PACKAGES: usize = 512;
const REPS: usize = 3;

fn parallel_config(workers: usize, batch_size: usize) -> HistoricalReplayConfigV1 {
    HistoricalReplayConfigV1 {
        worker_count: Some(workers),
        batch_size,
        parallel_threshold: 0,
    }
}

/// A closed snapshot of `PACKAGES` fully-verifiable packages: three unique
/// accepted voters followed by many duplicate re-votes (valid proofs, ledger-
/// rejected), so every package still runs full Triptych verification during
/// reconstruction — exactly the §21 cold-replay workload.
fn snapshot() -> GuiElectionSessionSnapshotV1 {
    let mut session = open_session();
    let _ = session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]));
    let _ = session.intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]));
    let _ = session.intake_ballot(&triptych_package_bytes(2, &[b"candidate-c"]));
    for _ in 3..PACKAGES {
        let _ = session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-b"]));
    }
    if let Err(error) = session.close() {
        panic!("fixture close must succeed: {error}");
    }
    match session.to_durable_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("fixture snapshot must encode: {error}"),
    }
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn time_serial(snapshot: &GuiElectionSessionSnapshotV1) -> u128 {
    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let start = Instant::now();
        let session = match GuiElectionSessionV1::from_durable_snapshot(snapshot.clone()) {
            Ok(session) => session,
            Err(error) => panic!("serial reconstruction must succeed: {error}"),
        };
        let elapsed = start.elapsed().as_micros();
        std::hint::black_box(&session);
        samples.push(elapsed);
    }
    median(samples)
}

fn time_parallel(snapshot: &GuiElectionSessionSnapshotV1, workers: usize, batch: usize) -> u128 {
    let config = parallel_config(workers, batch);
    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let start = Instant::now();
        let session =
            match GuiElectionSessionV1::from_durable_snapshot_parallel(snapshot.clone(), &config) {
                Ok(session) => session,
                Err(error) => panic!("parallel reconstruction must succeed: {error}"),
            };
        let elapsed = start.elapsed().as_micros();
        std::hint::black_box(&session);
        samples.push(elapsed);
    }
    median(samples)
}

#[test]
#[ignore = "manual release multicore reconstruction benchmark"]
fn release_multicore_perf_benchmark() {
    let profile = if cfg!(debug_assertions) {
        "DEBUG"
    } else {
        "RELEASE"
    };
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let budget = global_crypto_worker_budget_v1();
    println!(
        "PROBE profile={profile} available_parallelism={cores} global_worker_budget={budget} packages={PACKAGES}"
    );

    let snapshot = snapshot();

    // Warm up.
    let _ = time_parallel(&snapshot, 2, 16);

    let serial = time_serial(&snapshot);
    println!("CSV_HEADER,mode,workers,batch,wall_us,speedup_vs_serial");
    println!("CSV_ROW,serial,0,0,{serial},1.00");

    for workers in [1_usize, 2, 3, 4] {
        let wall = time_parallel(&snapshot, workers, 16);
        let speedup = serial as f64 / wall.max(1) as f64;
        println!("CSV_ROW,parallel,{workers},16,{wall},{speedup:.2}");
    }
}
