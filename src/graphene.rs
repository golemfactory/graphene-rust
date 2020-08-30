use std::io::{Error, ErrorKind, Result};
use std::{fs, mem, path::Path};

use crate::sgx::{self, SgxTargetInfo};

const GRAPHENE_OWN_TARGET_INFO_PATH: &str = "/dev/attestation/my_target_info";
const GRAPHENE_TARGET_INFO_PATH: &str = "/dev/attestation/target_info";
const GRAPHENE_USER_DATA_PATH: &str = "/dev/attestation/user_report_data";
const GRAPHENE_REPORT_PATH: &str = "/dev/attestation/report";
const GRAPHENE_QUOTE_PATH: &str = "/dev/attestation/quote";
const GRAPHENE_PF_KEY_PATH: &str = "/dev/attestation/protected_files_key";

/// Returns true if we're executing inside Graphene's SGX enclave
pub fn is_graphene_enclave() -> bool {
    // TODO: something more robust
    Path::new(GRAPHENE_QUOTE_PATH).exists()
}

/// Get SGX target info of the currently executing enclave.
pub fn get_target_info() -> Result<Vec<u8>> {
    fs::read(GRAPHENE_OWN_TARGET_INFO_PATH)
}

/// Get SGX report of the currently executing enclave.
/// `user_data` will be included in the report's `report_data` field
/// (max 64 bytes, will be padded with zeros if shorter).
pub fn get_report(target_info_bytes: &[u8], user_data: &[u8]) -> Result<Vec<u8>> {
    if target_info_bytes.len() != mem::size_of::<SgxTargetInfo>() {
        return Err(Error::from(ErrorKind::InvalidInput));
    }

    fs::write(GRAPHENE_TARGET_INFO_PATH, target_info_bytes)?;
    fs::write(
        GRAPHENE_USER_DATA_PATH,
        sgx::expand_report_data(user_data)?.as_ref(),
    )?;
    Ok(fs::read(GRAPHENE_REPORT_PATH)?)
}

/// Get SGX quote of the currently executing enclave.
/// `user_data` will be included in the quote's `report_data` field (max 64 bytes,
/// will be padded with zeros if shorter).
pub fn get_quote(user_data: &[u8]) -> Result<Vec<u8>> {
    fs::write(
        GRAPHENE_USER_DATA_PATH,
        sgx::expand_report_data(user_data)?.as_ref(),
    )?;
    Ok(fs::read(GRAPHENE_QUOTE_PATH)?)
}

/// Set master key for Protected Files.
/// The key is an AES-GCM-128 key in hex format (32 chars).
pub fn set_protected_files_key(key: &str) -> Result<()> {
    fs::write(GRAPHENE_PF_KEY_PATH, key.as_bytes())
}
