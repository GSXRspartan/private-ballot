//! Regression locks on the V2 anchor template's public ABI and event contract.
//!
//! Two layers:
//!
//! 1. Always-on source-contract locks: the exact module name, function
//!    signature (argument names, types, and order), event topic, and metadata
//!    keys must stay byte-for-byte identical in meaning. Any source change
//!    that alters the public contract fails these tests before a build.
//! 2. A compiled-artifact decode test (run with `-- --ignored`, after the
//!    wasm32 release build): it extracts the embedded `tari_tdef` custom
//!    section from the built WASM and decodes the template definition with
//!    the same template_abi version family the pinned `tari_template_lib`
//!    was built against, asserting the on-chain ABI (template name, exactly
//!    one stateless function, four `String` arguments in order, `Unit`
//!    output, no receiver, no constructor, and no `Type::WellKnown` member).

const LIB_RS: &str = include_str!("../src/lib.rs");
const CARGO_TOML: &str = include_str!("../Cargo.toml");
const ARTIFACT_NAME: &str = "tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm";

fn normalized(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn cargo_pins_the_current_mainnet_cohort_template_lib() {
    assert!(
        CARGO_TOML.contains("tari_template_lib = \"=0.40.0\""),
        "the template must build against the exact Tari Ootle v0.53 cohort template_lib"
    );
}

#[test]
fn source_contract_locks_module_and_function_signature() {
    let source = normalized(LIB_RS);
    assert!(
        source.contains("mod tari_private_ballot_anchor_v2"),
        "template module name changed"
    );
    assert!(
        source.contains(
            "pub fn publish_anchor_v2( anchor_digest: String, network: String, \
             election_id: String, public_summary: String, )"
        ),
        "publish_anchor_v2 argument names, types, or order changed"
    );
}

#[test]
fn source_contract_locks_event_topic_and_metadata_keys() {
    let source = normalized(LIB_RS);
    assert!(
        source.contains(
            "pub const ANCHOR_EVENT_TOPIC_V2: &str = \"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2\";"
        ),
        "event topic changed"
    );
    assert!(
        source.contains("pub const V2_DIGEST_KEY: &str = \"anchor_digest_v2\";"),
        "digest metadata key changed"
    );
    assert!(
        source.contains("pub const V2_NETWORK_KEY: &str = \"network\";"),
        "network metadata key changed"
    );
    assert!(
        source.contains("pub const V2_ELECTION_ID_KEY: &str = \"election_id\";"),
        "election_id metadata key changed"
    );
    assert!(
        source.contains("pub const V2_PUBLIC_SUMMARY_KEY: &str = \"public_summary\";"),
        "public_summary metadata key changed"
    );
}

#[test]
fn source_contract_stays_stateless() {
    let source = normalized(LIB_RS);
    assert!(
        source.contains("pub struct TariPrivateBallotAnchorV2;")
            && source.matches("pub struct").count() == 1,
        "the ABI carrier must stay the only, fieldless unit struct"
    );
    assert!(
        !source.contains("#[constructor]"),
        "the template must not declare a component constructor"
    );
}

/// Resolves the compiled artifact path: `PRIVATE_BALLOT_V2_WASM_PATH`
/// explicitly, else `<CARGO_TARGET_DIR>/wasm32-unknown-unknown/release/`,
/// else the crate-local `target/` directory.
fn artifact_path() -> Option<std::path::PathBuf> {
    let env_path = std::env::var("PRIVATE_BALLOT_V2_WASM_PATH").unwrap_or_default();
    if !env_path.is_empty() {
        return Some(std::path::PathBuf::from(env_path));
    }
    let base = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned());
    Some(
        std::path::PathBuf::from(base)
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(ARTIFACT_NAME),
    )
}

/// Extracts the payload of every custom section named `tari_tdef` from a
/// WASM binary (hand-rolled LEB128 scan; no external parser dependency).
fn tari_tdef_section_payloads(wasm: &[u8]) -> Result<Vec<&[u8]>, String> {
    if wasm.len() < 8 || wasm[..4] != [0x00, 0x61, 0x73, 0x6D] || wasm[4..8] != [1, 0, 0, 0] {
        return Err("not a WASM binary (bad magic/version)".to_owned());
    }
    let mut offset = 8;
    let mut sections = Vec::new();
    while offset < wasm.len() {
        let section_id = wasm[offset];
        offset += 1;
        let mut size: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = *wasm
                .get(offset)
                .ok_or("truncated WASM section size (LEB128)")?;
            offset += 1;
            size |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return Err("unreasonable LEB128 section size".to_owned());
            }
        }
        let end = offset
            .checked_add(usize::try_from(size).map_err(|_| "WASM section size exceeds usize")?)
            .ok_or("WASM section size overflow")?
            .min(wasm.len());
        let payload = wasm
            .get(offset..end)
            .ok_or("truncated WASM section payload")?;
        if section_id == 0 && !payload.is_empty() {
            // Custom section: [uleb name_len][name bytes][data]
            let mut name_len: u64 = 0;
            let mut shift = 0;
            let mut cursor = offset;
            loop {
                let byte = *payload
                    .get(cursor - offset)
                    .ok_or("truncated custom section name length")?;
                cursor += 1;
                name_len |= u64::from(byte & 0x7F) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            let name_len_usize = usize::try_from(name_len)
                .map_err(|_| "custom section name length exceeds usize")?;
            let name_end = (cursor - offset)
                .checked_add(name_len_usize)
                .ok_or("custom section name length overflow")?;
            let name = payload
                .get((cursor - offset)..name_end)
                .ok_or("truncated custom section name")?;
            if name == b"tari_tdef" {
                sections.push(payload.get(name_end..).ok_or("truncated tari_tdef data")?);
            }
        }
        offset = end;
    }
    Ok(sections)
}

/// The compiled artifact must embed exactly one template definition, and that
/// definition must match the frozen public ABI. Run after the wasm32 release
/// build: `cargo test -p ... --test abi_contract -- --ignored`.
#[test]
#[ignore = "requires the wasm32 release artifact; run with -- --ignored"]
fn built_artifact_abi_matches_the_frozen_contract() {
    use tari_template_abi::{FunctionKind, TemplateDef, Type};

    let path = artifact_path().expect("artifact path resolution");
    let wasm =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let payloads = tari_tdef_section_payloads(&wasm).expect("WASM section scan");
    assert_eq!(
        payloads.len(),
        1,
        "exactly one tari_tdef section is required; Ootle v0.53.2+ rejects binaries with two"
    );
    let payload = payloads[0];
    assert!(
        payload.len() >= 4,
        "tari_tdef payload too short for length prefix"
    );
    let full_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    assert!(
        full_len >= 4 && full_len <= payload.len(),
        "tari_tdef length prefix {full_len} exceeds section payload {}",
        payload.len()
    );
    let definition: TemplateDef = minicbor::Decoder::new(&payload[4..full_len])
        .decode()
        .expect("decode the embedded template definition");

    assert_eq!(definition.template_name(), "TariPrivateBallotAnchorV2");
    assert_eq!(
        definition.functions().len(),
        1,
        "the stateless anchor must expose exactly one function"
    );
    let publish = definition
        .get_function("publish_anchor_v2")
        .expect("publish_anchor_v2 must exist");
    assert!(
        matches!(publish.kind, FunctionKind::Function),
        "no receiver"
    );
    assert!(!publish.is_mut());
    let expected_args = ["anchor_digest", "network", "election_id", "public_summary"];
    assert_eq!(publish.arguments.len(), expected_args.len());
    for (argument, expected_name) in publish.arguments.iter().zip(expected_args) {
        assert_eq!(argument.name, expected_name);
        assert!(
            !matches!(argument.arg_type, Type::WellKnown(_)),
            "the four-string ABI must not carry WellKnown types"
        );
    }
    assert_eq!(publish.arguments[0].arg_type, Type::String);
    assert_eq!(publish.arguments[1].arg_type, Type::String);
    assert_eq!(publish.arguments[2].arg_type, Type::String);
    assert_eq!(publish.arguments[3].arg_type, Type::String);
    assert_eq!(publish.output, Type::Unit);
}
