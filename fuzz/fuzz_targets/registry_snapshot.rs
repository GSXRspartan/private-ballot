#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_cc_private_ballot_fuzz::fuzz_registry_snapshot;

fuzz_target!(|data: &[u8]| {
    fuzz_registry_snapshot(data);
});
