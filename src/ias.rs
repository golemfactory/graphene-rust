use anyhow::Result;
use http::{header::ToStrError, Error as HttpError};
use hyper::body::HttpBody as _;
use hyper::header::HeaderMap;
use hyper::{client::HttpConnector, Body, Client, Error as HyperError, Request};
use hyper_tls::HttpsConnector;
use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, sign::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sgx_types::sgx::{SgxEpidGroupId, SgxMeasurement, SgxQuote};
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

#[derive(thiserror::Error, Debug, Serialize, Deserialize)]
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
    Crypto(String),
}

impl From<IoError> for AttestationError {
    fn from(err: IoError) -> Self {
        AttestationError::Transport(err.to_string())
    }
}

impl From<HyperError> for AttestationError {
    fn from(err: HyperError) -> Self {
        AttestationError::Transport(err.to_string())
    }
}

impl From<HttpError> for AttestationError {
    fn from(err: HttpError) -> Self {
        AttestationError::Transport(err.to_string())
    }
}

impl From<ToStrError> for AttestationError {
    fn from(err: ToStrError) -> Self {
        AttestationError::Encoding(err.to_string())
    }
}

impl From<serde_json::Error> for AttestationError {
    fn from(err: serde_json::Error) -> Self {
        AttestationError::Encoding(err.to_string())
    }
}

impl From<base64::DecodeError> for AttestationError {
    fn from(err: base64::DecodeError) -> Self {
        AttestationError::InvalidResponse(err.to_string())
    }
}

impl From<u16> for AttestationError {
    fn from(response_code: u16) -> Self {
        AttestationError::IAS(response_code)
    }
}

impl From<ErrorStack> for AttestationError {
    fn from(err: ErrorStack) -> Self {
        AttestationError::Crypto(format!("OpenSSL error: {}", err))
    }
}

pub struct IasClient {
    https_client: Client<HttpsConnector<HttpConnector>>,
    production: bool,
}

impl IasClient {
    /// Initialize IAS client.
    /// If `production` is true, use production API endpoints.
    pub fn new(production: bool) -> Self {
        Self {
            https_client: Client::builder().build::<_, hyper::Body>(HttpsConnector::new()),
            production: production,
        }
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
        api_key: &str,
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
            .header("Ocp-Apim-Subscription-Key", api_key)
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
        api_key: &str,
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

                format!(
                    "{{\"isvEnclaveQuote\":\"{}\",\"nonce\":\"{}\"}}",
                    quote_base64, nonce
                )
            }
            None => format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64),
        };

        let req = Request::post(uri)
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", api_key)
            .body(Body::from(body))?;

        let mut resp = self.https_client.request(req).await?;

        if resp.status().as_u16() != 200 {
            return Err(resp.status().as_u16().into());
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp.body_mut().data().await {
            body.write_all(&chunk?)?;
        }

        AttestationResponse::from_response(resp.headers(), body)
    }
}

/// Raw bytes of IAS report and signature
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub report: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    pub advisory_url: Option<String>,
    pub advisory_ids: Option<Vec<String>>,
}

impl AttestationReport {
    /// Verify contents of an attestation report.
    pub fn verify(
        &self,
        allow_outdated: bool,
        nonce: Option<String>,
        report_data: Option<&[u8]>,
        mrenclave: Option<SgxMeasurement>,
        mrsigner: Option<SgxMeasurement>,
        isv_prod_id: Option<u16>,
        isv_svn: Option<u16>,
    ) -> Result<bool, AttestationError> {
        let quote = SgxQuote::from_bytes(&base64::decode(&self.isv_enclave_quote_body)?)?;

        if !self.isv_enclave_quote_status.eq_ignore_ascii_case("OK")
            && !(allow_outdated
                && self
                    .isv_enclave_quote_status
                    .eq_ignore_ascii_case("GROUP_OUT_OF_DATE"))
        {
            return Ok(false);
        }

        if self.nonce.as_deref() != nonce.as_deref() {
            return Ok(false);
        }

        if let Some(user_data) = report_data {
            if !quote.body.report_body.report_data.starts_with(user_data) {
                return Ok(false);
            }
        }

        if let Some(mr) = mrenclave {
            if mr != quote.body.report_body.mr_enclave {
                return Ok(false);
            }
        }

        if let Some(mr) = mrsigner {
            if mr != quote.body.report_body.mr_signer {
                return Ok(false);
            }
        }

        if let Some(id) = isv_prod_id {
            if id != quote.body.report_body.isv_prod_id {
                return Ok(false);
            }
        }

        if let Some(svn) = isv_svn {
            if svn != quote.body.report_body.isv_svn {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn unwrap_array(val: &Value) -> Result<Option<Vec<String>>, AttestationError> {
    match val.as_array() {
        None => Ok(None),
        Some(val) => {
            let mut rv = Vec::<String>::new();
            for el in val {
                match el.as_str() {
                    None => {
                        return Err(AttestationError::InvalidResponse(format!(
                            "missing report field: '{:?}'",
                            val
                        )))
                    }
                    Some(x) => rv.push(x.to_owned()),
                }
            }
            Ok(Some(rv))
        }
    }
}

impl TryFrom<AttestationResponse> for AttestationReport {
    type Error = AttestationError;

    fn try_from(raw: AttestationResponse) -> Result<Self, AttestationError> {
        let ias_key = PKey::public_key_from_pem(IAS_PUBLIC_KEY_PEM.as_bytes())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ias_key)?;
        verifier.update(&raw.report)?;
        if !verifier.verify(&raw.signature)? {
            return Err(AttestationError::InvalidResponse(
                "Invalid signature".to_string(),
            ));
        }

        let body: Value = serde_json::from_slice(&raw.report)?;
        Ok(AttestationReport {
            id: unwrap_body(&body["id"], true)?.unwrap(),
            timestamp: unwrap_body(&body["timestamp"], true)?.unwrap(),
            version: body["version"].as_u64().map(|x| x as u16).ok_or(
                AttestationError::InvalidResponse("missing report field: 'version'".to_string()),
            )?,
            isv_enclave_quote_status: unwrap_body(&body["isvEnclaveQuoteStatus"], true)?.unwrap(),
            isv_enclave_quote_body: unwrap_body(&body["isvEnclaveQuoteBody"], true)?.unwrap(),
            revocation_reason: unwrap_body(&body["revocationReason"], false)?,
            pse_manifest_status: unwrap_body(&body["pseManifestStatus"], false)?,
            pse_manifest_hash: unwrap_body(&body["pseManifestHash"], false)?,
            platform_info_blob: unwrap_body(&body["platformInfoBlob"], false)?,
            nonce: unwrap_body(&body["nonce"], false)?,
            epid_pseudonym: unwrap_body(&body["epidPseudonym"], false)?,
            advisory_url: unwrap_body(&body["advisoryURL"], false)?,
            advisory_ids: unwrap_array(&body["advisoryIDs"])?,
        })
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

fn unwrap_body(val: &Value, mandatory: bool) -> Result<Option<String>, AttestationError> {
    match val.as_str() {
        Some(val) => Ok(Some(val.to_owned())),
        None => {
            if mandatory {
                Err(AttestationError::InvalidResponse(format!(
                    "missing report field: '{}'",
                    val
                )))
            } else {
                Ok(None)
            }
        }
    }
}

impl AttestationResponse {
    fn from_response(headers: &HeaderMap, body: Vec<u8>) -> Result<Self, AttestationError> {
        Ok(Self {
            report: body,
            signature: base64::decode(
                &unwrap_header(headers, "x-iasreport-signature", true)?.unwrap(),
            )
            .map_err(|err| AttestationError::Encoding(err.to_string()))?,
        })
    }
}
