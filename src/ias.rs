use crate::sgx::{SgxEpidGroupId, SgxMeasurement, SgxQuote, SGX_FLAGS_DEBUG};
use anyhow::{anyhow, Result};
use http::{header::ToStrError, Error as HttpError};
use hyper::body::HttpBody as _;
use hyper::header::HeaderMap;
use hyper::{client::HttpConnector, Body, Client, Error as HyperError, Request};
use hyper_tls::HttpsConnector;
use openssl::{
    error::ErrorStack,
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Error as IoError, Write};

const BASE_URI_DEV: &str = "https://api.trustedservices.intel.com/sgx/dev";
const BASE_URI_PROD: &str = "https://api.trustedservices.intel.com/sgx";
const SIGRL_PATH: &str = "/attestation/v4/sigrl/";
const REPORT_PATH: &str = "/attestation/v4/report";

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

macro_rules! map_error {
    ($($type:ty => $error:path)*) => {
        $(
            impl From<$type> for AttestationError {
                fn from(err: $type) -> Self {
                    $error(err.to_string())
                }
            }
        )*
    };
}

map_error! {
    IoError => AttestationError::Transport
    HyperError => AttestationError::Transport
    HttpError => AttestationError::Transport
    ToStrError => AttestationError::Encoding
    serde_json::Error => AttestationError::Encoding
    base64::DecodeError => AttestationError::InvalidResponse
}

impl From<u16> for AttestationError {
    fn from(response_code: u16) -> Self {
        AttestationError::IAS(response_code)
    }
}

/// Raw bytes of IAS report and signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub report: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AttestationResponse {
    pub fn new(report: &[u8], signature: &[u8]) -> Self {
        AttestationResponse {
            report: report.to_owned(),
            signature: signature.to_owned(),
        }
    }

    pub fn verifier(self) -> AttestationVerifier {
        let mut valid = true;
        let rep = AttestationReport::try_from(&self);

        let mut verifier = AttestationVerifier {
            evidence: self,
            report: {
                if !rep.is_ok() {
                    valid = false;
                }
                rep.clone().unwrap_or_default()
            },
            hasher: Hasher::new(MessageDigest::sha512()).unwrap(),
            valid: valid,
            quote: if valid {
                let decoded = base64::decode(&rep.unwrap().isv_enclave_quote_body);
                match decoded {
                    Ok(val) => SgxQuote::from_bytes(&val).unwrap_or_default(),
                    Err(_) => {
                        valid = false;
                        SgxQuote::default()
                    }
                }
            } else {
                valid = false;
                SgxQuote::default()
            },
        };
        verifier.valid = valid;
        verifier
    }
}

pub struct AttestationVerifier {
    evidence: AttestationResponse,
    report: AttestationReport,
    quote: SgxQuote,
    hasher: Hasher,
    valid: bool,
}

impl AttestationVerifier {
    pub fn data(mut self, data: &[u8]) -> Self {
        if self.valid {
            // don't update validity, only check it at the end of verification since
            // this can be chained
            self.hasher.update(data).unwrap();
        }
        self
    }

    pub fn nonce(mut self, nonce: &str) -> Self {
        if self.valid && self.report.nonce.as_deref() != Some(nonce) {
            self.valid = false;
        }
        self
    }

    pub fn mr_enclave(mut self, mr: SgxMeasurement) -> Self {
        if self.valid && mr != self.quote.body.report_body.mr_enclave {
            self.valid = false;
        }
        self
    }

    pub fn mr_signer(mut self, mr: SgxMeasurement) -> Self {
        if self.valid && mr != self.quote.body.report_body.mr_signer {
            self.valid = false;
        }
        self
    }

    pub fn isv_prod_id(mut self, id: u16) -> Self {
        if self.valid && id != self.quote.body.report_body.isv_prod_id {
            self.valid = false;
        }
        self
    }

    pub fn isv_svn(mut self, svn: u16) -> Self {
        if self.valid && svn != self.quote.body.report_body.isv_svn {
            self.valid = false;
        }
        self
    }

    pub fn not_outdated(mut self) -> Self {
        if self.valid
            && self
                .report
                .isv_enclave_quote_status
                .eq_ignore_ascii_case("OK")
        {
            return self;
        }

        if self.valid
            && self
                .report
                .isv_enclave_quote_status
                .eq_ignore_ascii_case("GROUP_OUT_OF_DATE")
        {
            self.valid = false;
        }
        self
    }

    pub fn not_debug(mut self) -> Self {
        if self.valid && self.quote.body.report_body.attributes.flags & SGX_FLAGS_DEBUG != 0 {
            self.valid = false;
        }
        self
    }

    fn check_sig(&self) -> Result<()> {
        let ias_key = PKey::public_key_from_pem(IAS_PUBLIC_KEY_PEM.as_bytes())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ias_key)?;
        verifier.update(&self.evidence.report)?;
        if !verifier.verify(&self.evidence.signature)? {
            return Err(anyhow!("Invalid IAS signature"));
        }
        Ok(())
    }

    pub fn check(mut self) -> bool {
        if !self.valid {
            return false;
        }

        if !self.check_sig().is_ok() {
            return false;
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
            return false;
        }

        let hash = self.hasher.finish().unwrap();
        if !self
            .quote
            .body
            .report_body
            .report_data
            .starts_with(hash.as_ref())
        {
            return false;
        }
        true
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationRequest {
    nonce: Option<String>,
    isv_enclave_quote: String,
}

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
            production: production,
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
        Ok(serde_json::from_slice(&raw.report)?)
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
        report: body,
        signature: base64::decode(&unwrap_header(headers, "x-iasreport-signature", true)?.unwrap())
            .map_err(|err| AttestationError::Encoding(err.to_string()))?,
    })
}
