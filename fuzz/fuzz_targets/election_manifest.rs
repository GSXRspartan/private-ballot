#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_cc_private_ballot_fuzz::fuzz_election_manifest;

fuzz_target!(|data: &[u8]| {
    fuzz_election_manifest(data);
});
