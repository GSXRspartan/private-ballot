//! Organizer-local trusted Ootle anchor deployment lock.
//!
//! This stores only public deployment identity: network, template address, and
//! compiled template digest. Wallet credentials, bearer tokens, signer ids, and
//! election-specific anchor records are intentionally out of scope.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_EVENT_TOPIC_SUFFIX_V1, ANCHOR_TEMPLATE_MODULE_V1,
    AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};

use crate::error::GuiCoreError;
use crate::live_anchor_config::GuiLiveAnchorConfigRequestV1;

pub const TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_TRUSTED_OOTLE_DEPLOYMENT_V1";
pub const TRUSTED_OOTLE_DEPLOYMENT_FILENAME_V1: &str = "trusted-ootle-anchor-deployment-v1.json";
pub const TEMPLATE_ARTIFACT_DIGEST_ALGORITHM_ID_V1: &str = "BLAKE3-256";
pub const MAX_TEMPLATE_WASM_BYTES_V1: usize = 16 * 1024 * 1024;
const WASM_MAGIC: &[u8; 4] = b"\0asm";
const WASM_VERSION_1: &[u8; 4] = &[1, 0, 0, 0];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiTrustedOotleDeploymentV1 {
    pub schema: String,
    pub network: String,
    pub template_address: String,
    pub template_artifact_digest_hex: String,
    pub template_module: String,
    pub template_function: String,
    pub template_event_topic: String,
    pub locked_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiTrustedOotleDeploymentFixedV1 {
    pub schema: &'static str,
    pub template_module: &'static str,
    pub template_function: &'static str,
    pub template_event_topic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiTrustedOotleDeploymentStatusV1 {
    pub locked: bool,
    pub deployment: Option<GuiTrustedOotleDeploymentV1>,
    pub fixed: GuiTrustedOotleDeploymentFixedV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GuiTrustedOotleDeploymentLockRequestV1 {
    pub network: String,
    pub template_address: String,
    pub selected_wasm_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiTrustedOotleTemplateWasmInspectionV1 {
    pub display_filename: String,
    pub bytes: u64,
    pub digest_algorithm_id: &'static str,
    pub digest_hex: String,
}

#[must_use]
pub fn trusted_ootle_deployment_path_v1(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(TRUSTED_OOTLE_DEPLOYMENT_FILENAME_V1)
}

#[must_use]
pub fn trusted_ootle_deployment_fixed_v1() -> GuiTrustedOotleDeploymentFixedV1 {
    GuiTrustedOotleDeploymentFixedV1 {
        schema: TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1,
        template_module: ANCHOR_TEMPLATE_MODULE_V1,
        template_function: ANCHOR_EVENT_FUNCTION_V1,
        template_event_topic: trusted_ootle_deployment_event_topic_v1(),
    }
}

#[must_use]
pub fn trusted_ootle_deployment_event_topic_v1() -> String {
    format!("{ANCHOR_TEMPLATE_MODULE_V1}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}")
}

pub fn inspect_template_wasm_v1(
    path: &Path,
) -> Result<GuiTrustedOotleTemplateWasmInspectionV1, GuiCoreError> {
    let wasm = read_template_wasm_bytes(path)?;
    Ok(template_wasm_inspection_from_bytes(
        safe_template_wasm_display_filename(path),
        &wasm,
    ))
}

pub fn load_trusted_ootle_deployment_v1(
    app_data_dir: &Path,
) -> Result<GuiTrustedOotleDeploymentStatusV1, GuiCoreError> {
    let path = trusted_ootle_deployment_path_v1(app_data_dir);
    if !path.exists() {
        return Ok(unlocked_status());
    }
    let bytes =
        fs::read(&path).map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
    let deployment: GuiTrustedOotleDeploymentV1 = serde_json::from_slice(&bytes)
        .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?;
    validate_saved_deployment(&deployment)?;
    Ok(GuiTrustedOotleDeploymentStatusV1 {
        locked: true,
        deployment: Some(deployment),
        fixed: trusted_ootle_deployment_fixed_v1(),
    })
}

pub fn lock_trusted_ootle_deployment_v1(
    app_data_dir: &Path,
    request: &GuiTrustedOotleDeploymentLockRequestV1,
) -> Result<GuiTrustedOotleDeploymentStatusV1, GuiCoreError> {
    let path = trusted_ootle_deployment_path_v1(app_data_dir);
    if path.exists() {
        let _ = load_trusted_ootle_deployment_v1(app_data_dir)?;
        return Err(GuiCoreError::trusted_ootle_deployment_locked());
    }

    let inspected_wasm = inspect_template_wasm_v1(Path::new(&request.selected_wasm_path))?;
    let deployment = deployment_from_request(request, &inspected_wasm.digest_hex)?;
    fs::create_dir_all(app_data_dir)
        .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
    write_deployment_create_new(&path, &deployment)?;
    load_trusted_ootle_deployment_v1(app_data_dir)
}

pub fn unlock_trusted_ootle_deployment_v1(
    app_data_dir: &Path,
    confirm: bool,
) -> Result<GuiTrustedOotleDeploymentStatusV1, GuiCoreError> {
    if !confirm {
        return Err(GuiCoreError::trusted_ootle_deployment_unlock_not_confirmed());
    }
    let path = trusted_ootle_deployment_path_v1(app_data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(unlocked_status()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(unlocked_status()),
        Err(_) => Err(GuiCoreError::io_failure("trusted-ootle-deployment")),
    }
}

pub fn trusted_ootle_deployment_to_live_anchor_request_v1(
    mut request: GuiLiveAnchorConfigRequestV1,
    deployment: &GuiTrustedOotleDeploymentV1,
) -> Result<GuiLiveAnchorConfigRequestV1, GuiCoreError> {
    validate_saved_deployment(deployment)?;
    request.network = deployment.network.clone();
    request.template_address = deployment.template_address.clone();
    request.template_module = ANCHOR_TEMPLATE_MODULE_V1.to_owned();
    request.template_event_topic = trusted_ootle_deployment_event_topic_v1();
    request.template_artifact_digest_hex = deployment.template_artifact_digest_hex.clone();
    Ok(request)
}

fn unlocked_status() -> GuiTrustedOotleDeploymentStatusV1 {
    GuiTrustedOotleDeploymentStatusV1 {
        locked: false,
        deployment: None,
        fixed: trusted_ootle_deployment_fixed_v1(),
    }
}

fn deployment_from_request(
    request: &GuiTrustedOotleDeploymentLockRequestV1,
    template_artifact_digest_hex: &str,
) -> Result<GuiTrustedOotleDeploymentV1, GuiCoreError> {
    let network = request.network.trim().to_owned();
    let template_address = request.template_address.trim().to_owned();
    let template_artifact_digest_hex = template_artifact_digest_hex.trim().to_owned();
    let deployment = GuiTrustedOotleDeploymentV1 {
        schema: TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1.to_owned(),
        network,
        template_address,
        template_artifact_digest_hex,
        template_module: ANCHOR_TEMPLATE_MODULE_V1.to_owned(),
        template_function: ANCHOR_EVENT_FUNCTION_V1.to_owned(),
        template_event_topic: trusted_ootle_deployment_event_topic_v1(),
        locked_at_unix_ms: now_unix_ms()?,
    };
    validate_saved_deployment(&deployment)?;
    Ok(deployment)
}

fn validate_saved_deployment(
    deployment: &GuiTrustedOotleDeploymentV1,
) -> Result<AnchorTemplateBindingV1, GuiCoreError> {
    if deployment.schema != TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1
        || deployment.template_module != ANCHOR_TEMPLATE_MODULE_V1
        || deployment.template_function != ANCHOR_EVENT_FUNCTION_V1
        || deployment.template_event_topic != trusted_ootle_deployment_event_topic_v1()
    {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    let network = deployment.network.trim();
    if network != deployment.network {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    OotleNetworkIdV1::new(deployment.network.clone())
        .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?;
    AnchorTemplateBindingV1::new(
        deployment.template_address.clone(),
        ANCHOR_TEMPLATE_MODULE_V1.to_owned(),
        ANCHOR_EVENT_FUNCTION_V1.to_owned(),
        trusted_ootle_deployment_event_topic_v1(),
        parse_lower_digest_hex(&deployment.template_artifact_digest_hex)?,
    )
    .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())
}

fn parse_lower_digest_hex(hex: &str) -> Result<[u8; 32], GuiCoreError> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(bytes)
}

#[must_use]
pub fn template_wasm_digest_for_bytes_v1(bytes: &[u8]) -> [u8; 32] {
    Blake3HashProviderV1.hash(bytes)
}

fn read_template_wasm_bytes(path: &Path) -> Result<Vec<u8>, GuiCoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?;
    if metadata.is_symlink() || metadata.is_dir() || !metadata.is_file() {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    if metadata.len() == 0 || metadata.len() > MAX_TEMPLATE_WASM_BYTES_V1 as u64 {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    let bytes = fs::read(path).map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?;
    if bytes.is_empty() || bytes.len() > MAX_TEMPLATE_WASM_BYTES_V1 {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    if bytes.len() < WASM_MAGIC.len() + WASM_VERSION_1.len()
        || &bytes[..WASM_MAGIC.len()] != WASM_MAGIC
        || &bytes[WASM_MAGIC.len()..WASM_MAGIC.len() + WASM_VERSION_1.len()] != WASM_VERSION_1
    {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    Ok(bytes)
}

fn template_wasm_inspection_from_bytes(
    display_filename: String,
    bytes: &[u8],
) -> GuiTrustedOotleTemplateWasmInspectionV1 {
    GuiTrustedOotleTemplateWasmInspectionV1 {
        display_filename,
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        digest_algorithm_id: TEMPLATE_ARTIFACT_DIGEST_ALGORITHM_ID_V1,
        digest_hex: crate::hex::to_lower_hex(&template_wasm_digest_for_bytes_v1(bytes)),
    }
}

fn safe_template_wasm_display_filename(path: &Path) -> String {
    let leaf = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "template.wasm".to_owned());
    let sanitized: String = leaf
        .chars()
        .filter(|c| !matches!(c, '\\' | '/' | '\0') && !c.is_control())
        .take(255)
        .collect();
    if sanitized.is_empty() {
        "template.wasm".to_owned()
    } else {
        sanitized
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn write_deployment_create_new(
    path: &Path,
    deployment: &GuiTrustedOotleDeploymentV1,
) -> Result<(), GuiCoreError> {
    let tmp_path = path.with_extension(format!("json.tmp.{}", now_unix_ms()?));
    let bytes = serde_json::to_vec_pretty(deployment)
        .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
        file.write_all(&bytes)
            .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
        drop(file);
        if path.exists() {
            return Err(GuiCoreError::trusted_ootle_deployment_locked());
        }
        fs::rename(&tmp_path, path)
            .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
        let parent = path
            .parent()
            .ok_or_else(|| GuiCoreError::io_failure("trusted-ootle-deployment"))?;
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn now_unix_ms() -> Result<u64, GuiCoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| GuiCoreError::io_failure("trusted-ootle-deployment"))
}
