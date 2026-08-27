#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    tari_cc_private_ballot_cli::run_cli(std::env::args())
}
