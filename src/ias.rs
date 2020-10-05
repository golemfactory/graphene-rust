//! Attestation types and functions, IAS API.

use crate::sgx::{
    SgxMeasurement, SgxQuote, SGX_FLAGS_DEBUG, SGX_FLAGS_INITTED, SGX_FLAGS_MODE64BIT,
};
use anyhow::{anyhow, Result};
use chrono::{offset::Utc, DateTime, Duration};
use openssl::{
    error::ErrorStack,
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::Error as IoError;
use std::string::FromUtf8Error;

#[cfg(feature = "ias")]
pub mod online {
    use super::*;
    use crate::sgx::SgxEpidGroupId;
    use http::{header::ToStrError, Error as HttpError};
    use hyper::body::HttpBody as _;
    use hyper::header::HeaderMap;
    use hyper::{client::HttpConnector, Body, Client, Error as HyperError, Request};
    use hyper_tls::HttpsConnector;
    use std::io::Write;

    const BASE_URI_DEV: &str = "https://api.trustedservices.intel.com/sgx/dev";
    const BASE_URI_PROD: &str = "https://api.trustedservices.intel.com/sgx";
    const SIGRL_PATH: &str = "/attestation/v4/sigrl/";
    const REPORT_PATH: &str = "/attestation/v4/report";

    map_attestation_error! {
        HyperError => AttestationError::Transport
        HttpError => AttestationError::Transport
        ToStrError => AttestationError::Encoding
    }

    /// Interface for Intel Attestation Service.
    pub struct IasClient {
        https_client: Client<HttpsConnector<HttpConnector>>,
        production: bool,
        api_key: String,
    }

    impl IasClient {
        /// Initialize IAS client.
        /// If `production` is true, use production API endpoints.
        pub fn new(production: bool, api_key: &str) -> Self {
            Self {
                https_client: Client::builder().build::<_, hyper::Body>(HttpsConnector::new()),
                production,
                api_key: api_key.to_owned(),
            }
        }

        /// Initialize IAS client with production API endpoints.
        pub fn production(api_key: &str) -> Self {
            IasClient::new(true, api_key)
        }

        /// Initialize IAS client with development API endpoints.
        pub fn develop(api_key: &str) -> Self {
            IasClient::new(false, api_key)
        }

        fn uri(&self, suffix: &str) -> String {
            format!(
                "{}{}",
                if self.production {
                    BASE_URI_PROD
                } else {
                    BASE_URI_DEV
                },
                suffix
            )
        }

        /// Get signature revocation list for a given EPID group ID.
        pub async fn get_sigrl(
            &self,
            gid: &SgxEpidGroupId,
        ) -> Result<Option<Vec<u8>>, AttestationError> {
            let uri = format!(
                "{}{:02x}{:02x}{:02x}{:02x}",
                self.uri(SIGRL_PATH),
                gid[0],
                gid[1],
                gid[2],
                gid[3]
            );

            let req = Request::get(uri)
                .header("Ocp-Apim-Subscription-Key", &self.api_key)
                .body(Body::empty())?;

            let mut resp = self.https_client.request(req).await?;

            match resp.status().as_u16() {
                200 => (),
                //404 => return Ok(None), // this actually means that there is no such gid
                _ => return Err(resp.status().as_u16().into()),
            }

            match resp.headers().get("content-length") {
                None => {
                    return Err(AttestationError::InvalidResponse(
                        "Missing content-length".to_string(),
                    ))
                }
                Some(val) => {
                    if val == "0" {
                        return Ok(None); // no sigrl for this gid
                    }
                }
            }

            let mut sigrl = Vec::new();
            while let Some(chunk) = resp.body_mut().data().await {
                sigrl.write_all(&chunk?)?;
            }

            Ok(Some(sigrl))
        }

        /// Get IAS verification report and signature for an SGX enclave quote.
        pub async fn verify_attestation_evidence(
            &self,
            quote: &[u8],
            nonce: Option<String>,
        ) -> Result<AttestationResponse, AttestationError> {
            let uri = self.uri(REPORT_PATH);
            let quote_base64 = base64::encode(&quote);
            let body = match nonce {
                Some(nonce) => {
                    if nonce.len() > 32 {
                        return Err(AttestationError::InvalidArguments(
                            "Nonce too long".to_string(),
                        ));
                    }

                    serde_json::to_string(&AttestationRequest {
                        nonce: Some(nonce),
                        isv_enclave_quote: quote_base64,
                    })?
                }
                None => serde_json::to_string(&AttestationRequest {
                    nonce: None,
                    isv_enclave_quote: quote_base64,
                })?,
            };

            let req = Request::post(uri)
                .header("Content-type", "application/json")
                .header("Ocp-Apim-Subscription-Key", &self.api_key)
                .body(Body::from(body))?;

            let mut resp = self.https_client.request(req).await?;

            if resp.status().as_u16() != 200 {
                return Err(resp.status().as_u16().into());
            }

            let mut body = Vec::new();
            while let Some(chunk) = resp.body_mut().data().await {
                body.write_all(&chunk?)?;
            }

            create_response(resp.headers(), body)
        }
    }

    fn unwrap_header(
        headers: &HeaderMap,
        header_name: &str,
        mandatory: bool,
    ) -> Result<Option<String>, AttestationError> {
        match headers.get(header_name) {
            Some(val) => Ok(Some(val.to_str()?.to_owned())),
            None => {
                if mandatory {
                    Err(AttestationError::InvalidResponse(format!(
                        "missing header: '{}'",
                        header_name
                    )))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn create_response(
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<AttestationResponse, AttestationError> {
        Ok(AttestationResponse {
            report: String::from_utf8(body)?,
            signature: base64::decode(
                &unwrap_header(headers, "x-iasreport-signature", true)?.unwrap(),
            )
            .map_err(|err| AttestationError::Encoding(err.to_string()))?,
        })
    }
}

const IAS_PUBLIC_KEY_PEM: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFi
aGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhk
KWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQj
lytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwn
XnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KA
XJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4
tQIDAQAB
-----END PUBLIC KEY-----
"#;

#[derive(thiserror::Error, Clone, Debug)]
pub enum AttestationError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("IAS error: {0}")]
    IAS(u16),
    #[error("Invalid IAS response: {0}")]
    InvalidResponse(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] ErrorStack),
}

map_attestation_error! {
    IoError => AttestationError::Transport
    serde_json::Error => AttestationError::Encoding
    FromUtf8Error => AttestationError::Encoding
    base64::DecodeError => AttestationError::InvalidResponse
}

impl From<u16> for AttestationError {
    fn from(response_code: u16) -> Self {
        AttestationError::IAS(response_code)
    }
}

/// Raw bytes of IAS report and signature.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub report: String,
    pub signature: Vec<u8>,
}

impl AttestationResponse {
    /// Initialize the struct.
    pub fn new(report: String, signature: &[u8]) -> Self {
        AttestationResponse {
            report,
            signature: signature.to_owned(),
        }
    }

    /// Create attestation verifier from IAS response.
    pub fn verifier(self) -> AttestationVerifier {
        let mut result = AttestationResult::Ok;
        let rep = AttestationReport::try_from(&self);

        let mut verifier = AttestationVerifier {
            evidence: self,
            report: {
                if !rep.is_ok() {
                    result =
                        AttestationResult::InvalidIasReport("Failed to parse IAS report".into());
                }
                rep.clone().unwrap_or_default()
            },
            hasher: Hasher::new(MessageDigest::sha512()).unwrap(),
            result: AttestationResult::Ok,
            quote: if result.is_ok() {
                let decoded = base64::decode(&rep.unwrap().isv_enclave_quote_body);
                match decoded {
                    Ok(val) => SgxQuote::from_bytes(&val).unwrap_or_default(),
                    Err(_) => {
                        result = AttestationResult::InvalidIasReport(
                            "Failed to decode enclave quote".into(),
                        );
                        SgxQuote::default()
                    }
                }
            } else {
                SgxQuote::default()
            },
        };
        verifier.result = result;
        verifier
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttestationResult {
    Ok,
    InvalidIasReport(String),
    InvalidMrEnclave(String),
    InvalidMrSigner(String),
    InvalidIsvProdId(u16),
    InvalidIsvSvn(u16),
    InvalidQuoteStatus(String),
    InvalidFlags(String),
    InvalidReportData(String),
}

impl AttestationResult {
    /// Returns `true` if the attestation evidence passed all checks.
    pub fn is_ok(&self) -> bool {
        self == &AttestationResult::Ok
    }
}

const ENCLAVE_FLAGS_NEEDED: u64 = SGX_FLAGS_INITTED | SGX_FLAGS_MODE64BIT;

/// Attestation verifier enables easy checking of various attestation evidence properties.
///
/// # Example
///```no_run
/// use chrono::Duration;
/// use graphene::sgx::SgxQuote;
/// use graphene::AttestationResponse;
///
/// let user_data = [0u8; 42];
/// let quote = SgxQuote::hasher()
///     .data(&[0u8; 42])
///     .data(&[1u8; 10])
///     .build()
///     .unwrap();
/// let evidence = AttestationResponse::default(); // this should be obtained from IAS
/// let verifier = evidence.verifier();
/// let result = verifier.max_age(Duration::minutes(1))
///     .data(&[0u8; 42])
///     .data(&[1u8; 10])
///     .mr_enclave(quote.body.report_body.mr_enclave)
///     .isv_prod_id(42)
///     .not_debug()
///     .check();
///```
pub struct AttestationVerifier {
    evidence: AttestationResponse,
    report: AttestationReport,
    quote: SgxQuote,
    hasher: Hasher,
    result: AttestationResult,
}

impl AttestationVerifier {
    fn valid(&self) -> bool {
        self.result.is_ok()
    }

    /// Add custom data to hash. All bytes added using this method are hashed with `SHA512`
    /// and compared with enclave quote's `report_data` field.
    pub fn data(mut self, data: &[u8]) -> Self {
        if self.valid() {
            // don't update validity, only check it at the end of verification since
            // this can be chained
            self.hasher.update(data).unwrap();
        }
        self
    }

    /// Check IAS report's nonce.
    pub fn nonce(mut self, nonce: &str) -> Self {
        if self.valid() && self.report.nonce.as_deref() != Some(nonce) {
            self.result = AttestationResult::InvalidIasReport("Invalid nonce".into());
        }
        self
    }

    /// Check enclave's hash (must match the supplied value).
    pub fn mr_enclave(mut self, mr: SgxMeasurement) -> Self {
        if self.valid() && mr != self.quote.body.report_body.mr_enclave {
            self.result = AttestationResult::InvalidMrEnclave(hex::encode(
                self.quote.body.report_body.mr_enclave,
            ));
        }
        self
    }

    /// Check enclave's hash (must match any of the supplied values).
    pub fn mr_enclave_list(mut self, mrs: &[SgxMeasurement]) -> Self {
        if self.valid() && !mrs.contains(&self.quote.body.report_body.mr_enclave) {
            self.result = AttestationResult::InvalidMrEnclave(hex::encode(
                self.quote.body.report_body.mr_enclave,
            ));
        }
        self
    }

    /// Check enclave's hash of signing key (must match the supplied value).
    pub fn mr_signer(mut self, mr: SgxMeasurement) -> Self {
        if self.valid() && mr != self.quote.body.report_body.mr_signer {
            self.result = AttestationResult::InvalidMrSigner(hex::encode(
                self.quote.body.report_body.mr_signer,
            ));
        }
        self
    }

    /// Check enclave's hash of signing key (must match any of the supplied values).
    pub fn mr_signer_list(mut self, mrs: &[SgxMeasurement]) -> Self {
        if self.valid() && !mrs.contains(&self.quote.body.report_body.mr_signer) {
            self.result = AttestationResult::InvalidMrSigner(hex::encode(
                self.quote.body.report_body.mr_signer,
            ));
        }
        self
    }

    /// Check enclave's ISV product ID.
    pub fn isv_prod_id(mut self, id: u16) -> Self {
        if self.valid() && id != self.quote.body.report_body.isv_prod_id {
            self.result =
                AttestationResult::InvalidIsvProdId(self.quote.body.report_body.isv_prod_id);
        }
        self
    }

    /// Check enclave's security version number.
    pub fn isv_svn(mut self, svn: u16) -> Self {
        if self.valid() && svn != self.quote.body.report_body.isv_svn {
            self.result = AttestationResult::InvalidIsvSvn(self.quote.body.report_body.isv_svn);
        }
        self
    }

    /// Check that enclave's IAS status is not `GROUP_OUT_OF_DATE` (platform missing security
    /// updates).
    pub fn not_outdated(mut self) -> Self {
        if self.valid()
            && self
                .report
                .isv_enclave_quote_status
                .eq_ignore_ascii_case("OK")
        {
            return self;
        }

        if self.valid()
            && self
                .report
                .isv_enclave_quote_status
                .eq_ignore_ascii_case("GROUP_OUT_OF_DATE")
        {
            self.result = AttestationResult::InvalidQuoteStatus(
                self.report.isv_enclave_quote_status.to_owned(),
            );
        }
        self
    }

    /// Check that enclave is not in debug mode.
    pub fn not_debug(mut self) -> Self {
        if self.valid() && self.quote.body.report_body.attributes.flags & SGX_FLAGS_DEBUG != 0 {
            self.result = AttestationResult::InvalidFlags("Enclave has DEBUG flag enabled".into());
        }
        self
    }

    /// Check maximum age of the IAS report (using report's timestamp).
    pub fn max_age(mut self, age: Duration) -> Self {
        if self.valid() {
            let ts = DateTime::parse_from_rfc3339(&format!("{}Z", &self.report.timestamp));
            match ts {
                Ok(ts) => {
                    if ts + age < Utc::now() {
                        self.result =
                            AttestationResult::InvalidIasReport("IAS response is too old".into());
                    }
                }
                Err(_) => {
                    self.result =
                        AttestationResult::InvalidIasReport("Failed to parse IAS response".into());
                }
            }
        }
        self
    }

    fn check_sig(&mut self) -> Result<()> {
        let ias_key = PKey::public_key_from_pem(IAS_PUBLIC_KEY_PEM.as_bytes())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ias_key)?;
        verifier.update(&self.evidence.report.as_bytes())?;
        if !verifier.verify(&self.evidence.signature)? {
            self.result = AttestationResult::InvalidIasReport("Invalid IAS signature".into());
            return Err(anyhow!("Invalid IAS signature"));
        }
        Ok(())
    }

    /// Finalize all checks and convert the verifier into attestation result.
    pub fn check(mut self) -> AttestationResult {
        if !self.valid() {
            return self.result;
        }

        if !self.check_sig().is_ok() {
            return self.result;
        }

        // GROUP_OUT_OF_DATE is allowed unless filtered out by `not_outdated()`
        if !self
            .report
            .isv_enclave_quote_status
            .eq_ignore_ascii_case("OK")
            && !self
                .report
                .isv_enclave_quote_status
                .eq_ignore_ascii_case("GROUP_OUT_OF_DATE")
        {
            self.result =
                AttestationResult::InvalidQuoteStatus(self.report.isv_enclave_quote_status);
            return self.result;
        }

        if self.quote.body.report_body.attributes.flags & ENCLAVE_FLAGS_NEEDED
            != ENCLAVE_FLAGS_NEEDED
        {
            self.result =
                AttestationResult::InvalidFlags("Enclave is not initialized or not 64bit".into());
            return self.result;
        }

        let hash = self.hasher.finish().unwrap();
        if !self
            .quote
            .body
            .report_body
            .report_data
            .starts_with(hash.as_ref())
        {
            self.result = AttestationResult::InvalidReportData(hex::encode(
                &self.quote.body.report_body.report_data[..],
            ));
            return self.result;
        }
        self.result
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationRequest {
    nonce: Option<String>,
    isv_enclave_quote: String,
}

/// IAS attestation report. See IAS API specification for details.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationReport {
    pub id: String,
    pub timestamp: String,
    pub version: u16,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    #[serde(rename = "advisoryURL")]
    pub advisory_url: Option<String>,
    #[serde(rename = "advisoryIDs")]
    pub advisory_ids: Option<Vec<String>>,
}

impl TryFrom<&AttestationResponse> for AttestationReport {
    type Error = AttestationError;

    fn try_from(raw: &AttestationResponse) -> Result<Self, AttestationError> {
        Ok(serde_json::from_str(&raw.report)?)
    }
}
