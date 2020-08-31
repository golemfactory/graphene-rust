use byteorder::{LittleEndian, ReadBytesExt};
use hex;
use std::fmt::{self, Debug, Formatter};
use std::io::{Cursor, Error, ErrorKind, Read, Result};
use std::mem;

use crate::graphene;

// Enclave Flags Bit Masks
pub const SGX_FLAGS_INITTED: u64 = 0x0000_0000_0000_0001;
pub const SGX_FLAGS_DEBUG: u64 = 0x0000_0000_0000_0002;
pub const SGX_FLAGS_MODE64BIT: u64 = 0x0000_0000_0000_0004;
pub const SGX_FLAGS_PROVISION_KEY: u64 = 0x0000_0000_0000_0010;
pub const SGX_FLAGS_EINITTOKEN_KEY: u64 = 0x0000_0000_0000_0020;
pub const SGX_FLAGS_KSS: u64 = 0x0000_0000_0000_0080;
pub const SGX_FLAGS_RESERVED: u64 = !(SGX_FLAGS_INITTED
    | SGX_FLAGS_DEBUG
    | SGX_FLAGS_MODE64BIT
    | SGX_FLAGS_PROVISION_KEY
    | SGX_FLAGS_EINITTOKEN_KEY
    | SGX_FLAGS_KSS);

// XSAVE Feature Request Mask
pub const SGX_XFRM_LEGACY: u64 = 0x0000_0000_0000_0003;
pub const SGX_XFRM_AVX: u64 = 0x0000_0000_0000_0006;
pub const SGX_XFRM_AVX512: u64 = 0x0000_0000_0000_00E6;
pub const SGX_XFRM_MPX: u64 = 0x0000_0000_0000_0018;
pub const SGX_XFRM_RESERVED: u64 = !(SGX_XFRM_LEGACY | SGX_XFRM_AVX);

pub type SgxMiscSelect = u32;
pub type SgxKey = [u8; 16];
pub type SgxKeyId = [u8; 32];
pub type SgxIsvSvn = u16;
pub type SgxConfigSvn = u16;
pub type SgxConfigId = [u8; 64];
pub type SgxCpuSvn = [u8; 16];
pub type SgxSpid = [u8; 16];
pub type SgxBasename = [u8; 32];
pub type SgxEpidGroupId = [u8; 4];

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SgxQuoteSignType {
    UnlinkableSignature = 0,
    LinkableSignature = 1,
}

impl_struct! {
    pub struct SgxAttributes {
        pub flags: u64,
        pub xfrm: u64,
    }

    pub struct SgxMiscAttribute {
        pub secs_attr: SgxAttributes,
        pub misc_select: SgxMiscSelect,
    }

    pub struct SgxTargetInfo {
        pub mr_enclave: SgxMeasurement,
        pub attributes: SgxAttributes,
        pub reserved1: [u8; 2],
        pub config_svn: SgxConfigSvn,
        pub misc_select: SgxMiscSelect,
        pub reserved2: [u8; 8],
        pub config_id: SgxConfigId,
        pub reserved3: [u8; 384],
        bytes: Vec<u8>,
    }

    pub struct SgxReportBody {
        pub cpu_svn: SgxCpuSvn,
        pub misc_select: SgxMiscSelect,
        pub reserved1: [u8; 12],
        pub isv_ext_prod_id: SgxIsvExtProdId,
        pub attributes: SgxAttributes,
        pub mr_enclave: SgxMeasurement,
        pub reserved2: [u8; 32],
        pub mr_signer: SgxMeasurement,
        pub reserved3: [u8; 32],
        pub config_id: SgxConfigId,
        pub isv_prod_id: SgxProdId,
        pub isv_svn: SgxIsvSvn,
        pub config_svn: SgxConfigSvn,
        pub reserved4: [u8; 42],
        pub isv_family_id: SgxIsvFamilyId,
        pub report_data: SgxReportData,
    }

    pub struct SgxReport {
        pub body: SgxReportBody,
        pub key_id: SgxKeyId,
        pub mac: SgxMac,
    }

    pub struct SgxQuoteBody {
        pub version: u16,
        pub sign_type: u16,
        pub epid_group_id: SgxEpidGroupId,
        pub qe_svn: SgxIsvSvn,
        pub pce_svn: SgxIsvSvn,
        pub xeid: u32,
        pub basename: SgxBasename,
        pub report_body: SgxReportBody,
    }
}

pub struct SgxQuote {
    pub body: SgxQuoteBody,
    pub signature_len: u32,
    pub signature: Option<Vec<u8>>,
}

pub const SGX_HASH_SIZE: usize = 32;
pub const SGX_MAC_SIZE: usize = 16;
pub const SGX_REPORT_DATA_SIZE: usize = 64;

pub type SgxProdId = u16;
pub type SgxIsvExtProdId = [u8; 16];
pub type SgxIsvFamilyId = [u8; 16];
pub type SgxMeasurement = [u8; SGX_HASH_SIZE];
pub type SgxMac = [u8; SGX_MAC_SIZE];
pub type SgxReportData = [u8; SGX_REPORT_DATA_SIZE];

pub fn expand_report_data(user_data: &[u8]) -> Result<SgxReportData> {
    let user_data_len = user_data.len();
    if user_data_len > SGX_REPORT_DATA_SIZE {
        return Err(Error::from(ErrorKind::InvalidInput));
    }

    let mut report_data = [0; SGX_REPORT_DATA_SIZE];
    report_data[0..user_data_len].copy_from_slice(user_data);
    Ok(report_data)
}

impl Debug for SgxTargetInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "")?;
        writeln!(f, "mr_enclave       : {}", hex::encode(self.mr_enclave))?;
        writeln!(f, "attributes.flags : {:02x}", self.attributes.flags)?;
        writeln!(f, "attributes.xfrm  : {:02x}", self.attributes.xfrm)?;
        #[cfg(feature = "verbose")]
        writeln!(f, "reserved1        : {}", hex::encode(self.reserved1))?;
        writeln!(f, "config_svn       : {:02x}", self.config_svn)?;
        writeln!(f, "misc_select      : {:02x}", self.misc_select)?;
        #[cfg(feature = "verbose")]
        writeln!(f, "reserved2        : {}", hex::encode(self.reserved2))?;
        write!(f, "config_id        : {}", hex::encode(&self.config_id[..]))?;
        #[cfg(feature = "verbose")]
        write!(f, "reserved3        : {}", hex::encode(&self.reserved3[..]))?;
        Ok(())
    }
}

impl AsRef<[u8]> for SgxTargetInfo {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Into<Vec<u8>> for SgxTargetInfo {
    fn into(self) -> Vec<u8> {
        self.bytes
    }
}

impl SgxTargetInfo {
    pub fn size_raw() -> usize {
        offset_of!(SgxTargetInfo, bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SgxTargetInfo::size_raw() {
            return Err(Error::from(ErrorKind::InvalidData));
        }

        let mut reader = Cursor::new(bytes);
        let mut info = Self::default();

        info.bytes = bytes.to_owned();
        reader.read_exact(&mut info.mr_enclave)?;
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

    pub fn from_enclave() -> Result<Self> {
        SgxTargetInfo::from_bytes(&graphene::get_target_info()?)
    }
}

impl Debug for SgxReportBody {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, " cpu_svn          : {}", hex::encode(self.cpu_svn))?;
        writeln!(f, " misc_select      : {:02x}", self.misc_select)?;
        #[cfg(feature = "verbose")]
        writeln!(f, " reserved1        : {:02x?}", self.reserved1)?;
        writeln!(
            f,
            " isv_ext_prod_id  : {}",
            hex::encode(self.isv_ext_prod_id)
        )?;
        writeln!(f, " attributes.flags : {:02x}", self.attributes.flags)?;
        writeln!(f, " attributes.xfrm  : {:02x}", self.attributes.xfrm)?;
        writeln!(f, " mr_enclave       : {}", hex::encode(self.mr_enclave))?;
        #[cfg(feature = "verbose")]
        writeln!(f, " reserved2        : {}", hex::encode(self.reserved2))?;
        writeln!(f, " mr_signer        : {}", hex::encode(self.mr_signer))?;
        #[cfg(feature = "verbose")]
        writeln!(f, " reserved3        : {}", hex::encode(self.reserved3))?;
        writeln!(
            f,
            " config_id        : {}",
            hex::encode(&self.config_id[..])
        )?;
        writeln!(f, " isv_prod_id      : {:02x}", self.isv_prod_id)?;
        writeln!(f, " isv_svn          : {:02x}", self.isv_svn)?;
        writeln!(f, " config_svn       : {:02x}", self.config_svn)?;
        #[cfg(feature = "verbose")]
        writeln!(
            f,
            " reserved4        : {}",
            hex::encode(&self.reserved4[..])
        )?;
        writeln!(f, " isv_family_id    : {}", hex::encode(self.isv_family_id))?;
        write!(
            f,
            " report_data      : {}",
            hex::encode(&self.report_data[..])
        )
    }
}

impl SgxReportBody {
    pub fn from_reader<T: Read>(reader: &mut T) -> Result<Self> {
        let mut body = SgxReportBody::default();

        reader.read_exact(&mut body.cpu_svn)?;
        body.misc_select = reader.read_u32::<LittleEndian>()?;
        reader.read_exact(&mut body.reserved1)?;
        reader.read_exact(&mut body.isv_ext_prod_id)?;
        body.attributes.flags = reader.read_u64::<LittleEndian>()?;
        body.attributes.xfrm = reader.read_u64::<LittleEndian>()?;
        reader.read_exact(&mut body.mr_enclave)?;
        reader.read_exact(&mut body.reserved2)?;
        reader.read_exact(&mut body.mr_signer)?;
        reader.read_exact(&mut body.reserved3)?;
        reader.read_exact(&mut body.config_id)?;
        body.isv_prod_id = reader.read_u16::<LittleEndian>()?;
        body.isv_svn = reader.read_u16::<LittleEndian>()?;
        body.config_svn = reader.read_u16::<LittleEndian>()?;
        reader.read_exact(&mut body.reserved4)?;
        reader.read_exact(&mut body.isv_family_id)?;
        reader.read_exact(&mut body.report_data)?;

        Ok(body)
    }
}

impl Debug for SgxReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nreport_body:\n{:?}", self.body)?;
        writeln!(f, "key_id           : {}", hex::encode(self.key_id))?;
        write!(f, "mac              : {}", hex::encode(self.mac))
    }
}

impl SgxReport {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }

        let mut reader = Cursor::new(bytes);
        let mut report = Self::default();

        report.body = SgxReportBody::from_reader(&mut reader)?;
        reader.read_exact(&mut report.key_id)?;
        reader.read_exact(&mut report.mac)?;

        Ok(report)
    }
}

impl Debug for SgxQuote {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "")?;
        writeln!(f, "version           : {:02x}", self.body.version)?;
        writeln!(f, "sign_type         : {:02x}", self.body.sign_type)?;
        writeln!(
            f,
            "epid_group_id     : {}",
            hex::encode(self.body.epid_group_id)
        )?;
        writeln!(f, "qe_svn            : {:02x}", self.body.qe_svn)?;
        writeln!(f, "pce_svn           : {:02x}", self.body.pce_svn)?;
        writeln!(f, "xeid              : {:04x}", self.body.xeid)?;
        writeln!(f, "basename          : {}", hex::encode(self.body.basename))?;
        writeln!(f, "report_body       :\n{:?}", self.body.report_body)?;
        write!(f, "signature_len     : {:04x}", self.signature_len)
    }
}

impl SgxQuote {
    /// Parses raw quote bytes into `SgxQuote`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let quote_size = bytes.len();

        // `SgxQuoteBody` is packed so we can do the math below.
        // IAS quotes lack the `signature_len` and `signature` fields (they are SgxQuoteBody).
        let min_size = mem::size_of::<SgxQuoteBody>();

        if quote_size < min_size {
            return Err(Error::from(ErrorKind::InvalidData));
        }

        let mut reader = Cursor::new(bytes);
        let mut body = SgxQuoteBody::default();

        body.version = reader.read_u16::<LittleEndian>()?;
        body.sign_type = reader.read_u16::<LittleEndian>()?;
        reader.read_exact(&mut body.epid_group_id)?;
        body.qe_svn = reader.read_u16::<LittleEndian>()?;
        body.pce_svn = reader.read_u16::<LittleEndian>()?;
        body.xeid = reader.read_u32::<LittleEndian>()?;
        reader.read_exact(&mut body.basename)?;
        body.report_body = SgxReportBody::from_reader(&mut reader)?;

        if quote_size == min_size {
            // IAS quote, no signature
            return Ok(SgxQuote {
                body: body,
                signature_len: 0,
                signature: None,
            });
        } else {
            let sig_len = reader.read_u32::<LittleEndian>()?;

            if quote_size
                != mem::size_of::<SgxQuoteBody>() + mem::size_of::<u32>() + sig_len as usize
            {
                return Err(Error::from(ErrorKind::InvalidData));
            }

            let mut sig = vec![0; sig_len as usize];
            reader.read_exact(&mut sig)?;
            Ok(SgxQuote {
                body: body,
                signature_len: sig_len,
                signature: Some(sig),
            })
        }
    }
}
