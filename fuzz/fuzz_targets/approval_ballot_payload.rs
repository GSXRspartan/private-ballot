#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_cc_private_ballot_fuzz::fuzz_approval_ballot_payload;

fuzz_target!(|data: &[u8]| {
    fuzz_approval_ballot_payload(data);
});
