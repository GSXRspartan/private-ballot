#![forbid(unsafe_code)]

use tari_cc_private_ballot_protocol::{PROTOCOL_VERSION_V1, TEST_ONLY_SUITE_ID};

fn main() {
    println!("Tari CC Private Ballot protocol workspace");
    println!("protocol version: {PROTOCOL_VERSION_V1}");
    println!("test-only suite: {TEST_ONLY_SUITE_ID}");
    println!("binding elections: disabled");
}
