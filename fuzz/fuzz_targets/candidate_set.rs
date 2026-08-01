#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_cc_private_ballot_fuzz::fuzz_candidate_set;

fuzz_target!(|data: &[u8]| {
    fuzz_candidate_set(data);
});
