use byteorder::{LittleEndian, ReadBytesExt};
pub use sgx_types::{sgx_quote_t, sgx_report_body_t, sgx_report_t, sgx_target_info_t};
use std::io::{Cursor, Error, ErrorKind, Read, Result};
use std::{fs, mem, path::Path};

const GRAPHENE_OWN_TARGET_INFO_PATH: &str = "/dev/attestation/my_target_info";
const GRAPHENE_TARGET_INFO_PATH: &str = "/dev/attestation/target_info";
const GRAPHENE_USER_DATA_PATH: &str = "/dev/attestation/user_report_data";
const GRAPHENE_QUOTE_PATH: &str = "/dev/attestation/quote";
const GRAPHENE_PF_KEY_PATH: &str = "/dev/attestation/protected_files_key";

pub struct EnclaveQuote {
    pub quote: sgx_quote_t,
    pub signature: Vec<u8>,
}

/// Returns true if we're executing inside Graphene's SGX enclave
pub fn is_graphene_enclave() -> bool {
    // TODO: something more robust
    Path::new(GRAPHENE_QUOTE_PATH).exists()
}

pub fn get_target_info_bytes() -> Result<Vec<u8>> {
    fs::read(GRAPHENE_OWN_TARGET_INFO_PATH)
}

/// Get SGX target info of the currently executing enclave.
pub fn get_target_info() -> Result<sgx_target_info_t> {
    let info_bytes = get_target_info_bytes()?;

    if info_bytes.len() < mem::size_of::<sgx_target_info_t>() {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    let mut reader = Cursor::new(info_bytes);
    let mut info = sgx_target_info_t::default();

    reader.read_exact(&mut info.mr_enclave.m)?;
    info.attributes.flags = reader.read_u64::<LittleEndian>()?;
    info.attributes.xfrm = reader.read_u64::<LittleEndian>()?;
    reader.read_exact(&mut info.reserved1)?;
    info.config_svn = reader.read_u16::<LittleEndian>()?;
    info.misc_select = reader.read_u32::<LittleEndian>()?;
    reader.read_exact(&mut info.reserved2)?;
    reader.read_exact(&mut info.config_id)?;
    reader.read_exact(&mut info.reserved3)?;

    Ok(info)
}

pub fn display_target_info(info: &sgx_target_info_t) {
    println!(" mr_enclave       : {:02x?}", &info.mr_enclave.m);
    println!(" attributes.flags : {:02x}", &info.attributes.flags);
    println!(" attributes.xfrm  : {:02x}", &info.attributes.xfrm);
    //println!(" reserved1        : {:02x?}", &info.reserved1);
    println!(" config_svn       : {:02x}", &info.config_svn);
    println!(" misc_select      : {:02x}", &info.misc_select);
    //println!(" reserved2        : {:02x?}", &info.reserved2);
    println!(" config_id        : {:02x?}", &info.config_id[..]);
    //println!(" reserved3        : {:02x?}", &info.reserved3[..]);
}

fn read_report_body(reader: &mut Cursor<Vec<u8>>) -> Result<sgx_report_body_t> {
    let mut body = sgx_report_body_t::default();

    reader.read_exact(&mut body.cpu_svn.svn)?;
    body.misc_select = reader.read_u32::<LittleEndian>()?;
    reader.read_exact(&mut body.reserved1)?;
    reader.read_exact(&mut body.isv_ext_prod_id)?;
    body.attributes.flags = reader.read_u64::<LittleEndian>()?;
    body.attributes.xfrm = reader.read_u64::<LittleEndian>()?;
    reader.read_exact(&mut body.mr_enclave.m)?;
    reader.read_exact(&mut body.reserved2)?;
    reader.read_exact(&mut body.mr_signer.m)?;
    reader.read_exact(&mut body.reserved3)?;
    reader.read_exact(&mut body.config_id)?;
    body.isv_prod_id = reader.read_u16::<LittleEndian>()?;
    body.isv_svn = reader.read_u16::<LittleEndian>()?;
    body.config_svn = reader.read_u16::<LittleEndian>()?;
    reader.read_exact(&mut body.reserved4)?;
    reader.read_exact(&mut body.isv_family_id)?;
    reader.read_exact(&mut body.report_data.d)?;

    Ok(body)
}

pub fn display_report_body(body: &sgx_report_body_t) {
    println!(" cpu_svn          : {:02x?}", &body.cpu_svn.svn);
    println!(" misc_select      : {:02x}", &body.misc_select);
    //println!(" reserved1        : {:02x?}", &body.reserved1);
    println!(" isv_ext_prod_id  : {:02x?}", &body.isv_ext_prod_id);
    println!(" attributes.flags : {:02x}", &body.attributes.flags);
    println!(" attributes.xfrm  : {:02x}", &body.attributes.xfrm);
    println!(" mr_enclave       : {:02x?}", &body.mr_enclave.m);
    //println!(" reserved2        : {:02x?}", &body.reserved2);
    println!(" mr_signer        : {:02x?}", &body.mr_signer.m);
    //println!(" reserved3        : {:02x?}", &body.reserved3);
    println!(" config_id        : {:02x?}", &body.config_id[..]);
    println!(" isv_prod_id      : {:02x}", &body.isv_prod_id);
    println!(" isv_svn          : {:02x}", &body.isv_svn);
    println!(" config_svn       : {:02x}", &body.config_svn);
    //println!(" reserved4        : {:02x?}", &body.reserved4[..]);
    println!(" isv_family_id    : {:02x?}", &body.isv_family_id);
    println!(" report_data      : {:02x?}", &body.report_data.d[..]);
}

pub fn display_report(report: &sgx_report_t) {
    display_report_body(&report.body);
    println!(" key_id           : {:02x?}", &report.key_id.id);
    println!(" mac              : {:02x?}", &report.mac);
}

fn expand_report_data(user_data: &[u8]) -> Result<[u8; 64]> {
    let user_data_len = user_data.len();
    if user_data_len > 64 {
        return Err(Error::from(ErrorKind::InvalidInput));
    }

    let mut report_data = [0; 64];
    report_data[0..user_data_len].copy_from_slice(user_data);
    Ok(report_data)
}

/// Get SGX report of the currently executing enclave (raw bytes).
/// `user_data` will be included in the report's `report_data` field
/// (max 64 bytes, will be padded with zeros if shorter).
pub fn get_report_bytes(target_info_bytes: &[u8], user_data: &[u8]) -> Result<Vec<u8>> {
    if target_info_bytes.len() != mem::size_of::<sgx_target_info_t>() {
        return Err(Error::from(ErrorKind::InvalidInput));
    }
    fs::write(GRAPHENE_TARGET_INFO_PATH, target_info_bytes)?;
    fs::write(
        GRAPHENE_USER_DATA_PATH,
        expand_report_data(user_data)?.to_vec(),
    )?;
    Ok(fs::read(GRAPHENE_QUOTE_PATH)?)
}

/// Get SGX report of the currently executing enclave.
/// `user_data` will be included in the report's `report_data` field
/// (max 64 bytes, will be padded with zeros if shorter).
pub fn get_report(target_info_bytes: &[u8], user_data: &[u8]) -> Result<sgx_report_t> {
    if target_info_bytes.len() != mem::size_of::<sgx_target_info_t>() {
        return Err(Error::from(ErrorKind::InvalidInput));
    }

    fs::write(GRAPHENE_TARGET_INFO_PATH, target_info_bytes)?;
    fs::write(
        GRAPHENE_USER_DATA_PATH,
        expand_report_data(user_data)?.to_vec(),
    )?;

    let report_bytes = get_report_bytes(target_info_bytes, user_data)?;
    let mut reader = Cursor::new(report_bytes);
    let mut report = sgx_report_t::default();

    report.body = read_report_body(&mut reader)?;
    reader.read_exact(&mut report.key_id.id)?;
    reader.read_exact(&mut report.mac)?;

    Ok(report)
}

/// Get SGX quote of the currently executing enclave (raw bytes).
/// `user_data` will be included in the quote's `report_data` field
/// (max 64 bytes, will be padded with zeros if shorter).
pub fn get_quote_bytes(user_data: &[u8]) -> Result<Vec<u8>> {
    fs::write(
        GRAPHENE_USER_DATA_PATH,
        expand_report_data(user_data)?.to_vec(),
    )?;
    Ok(fs::read(GRAPHENE_QUOTE_PATH)?)
}

/// Get SGX quote of the currently executing enclave (parsed into EnclaveQuote).
/// `user_data` will be included in the quote's `report_data` field (max 64 bytes,
/// will be padded with zeros if shorter).
pub fn get_quote(user_data: &[u8]) -> Result<EnclaveQuote> {
    let quote_bytes = get_quote_bytes(user_data)?;
    let quote_size = quote_bytes.len();

    if quote_size < mem::size_of::<sgx_quote_t>() {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    let mut reader = Cursor::new(quote_bytes);
    let mut quote = sgx_quote_t::default();

    quote.version = reader.read_u16::<LittleEndian>()?;
    quote.sign_type = reader.read_u16::<LittleEndian>()?;
    reader.read_exact(&mut quote.epid_group_id)?;
    quote.qe_svn = reader.read_u16::<LittleEndian>()?;
    quote.pce_svn = reader.read_u16::<LittleEndian>()?;
    quote.xeid = reader.read_u32::<LittleEndian>()?;
    reader.read_exact(&mut quote.basename.name)?;
    quote.report_body = read_report_body(&mut reader)?;
    quote.signature_len = reader.read_u32::<LittleEndian>()?;

    if quote_size != mem::size_of::<sgx_quote_t>() + quote.signature_len as usize {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    let mut sig = vec![0; quote.signature_len as usize];
    reader.read_exact(&mut sig)?;

    Ok(EnclaveQuote {
        quote: quote,
        signature: sig,
    })
}

pub unsafe fn display_quote(quote: &sgx_quote_t) {
    println!("version           : {:02x}", quote.version);
    println!("sign_type         : {:02x}", quote.sign_type);
    println!("epid_group_id     : {:02x?}", quote.epid_group_id);
    println!("qe_svn            : {:02x}", quote.qe_svn);
    println!("pce_svn           : {:02x}", quote.pce_svn);
    println!("xeid              : {:04x}", quote.xeid);
    println!("basename          : {:02x?}", quote.basename.name);
    println!("report_body       :");
    display_report_body(&quote.report_body);
    println!("signature_len     : {:04x}", quote.signature_len);
}

/// Set master key for Protected Files.
/// The key is an AES-GCM-128 key in hex format (32 chars).
pub fn set_protected_files_key(key: &str) -> Result<()> {
    fs::write(GRAPHENE_PF_KEY_PATH, key.as_bytes())
}
