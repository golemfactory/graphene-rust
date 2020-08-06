use hyper::body::HttpBody as _;
use hyper::header::HeaderMap;
use hyper::{client::HttpConnector, Body, Client, Request};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const SIGRL_PATH: &str = "/attestation/v4/sigrl/";
const REPORT_PATH: &str = "/attestation/v4/report";

pub struct IasClient {
    https_client: Client<HttpsConnector<HttpConnector>>,
}

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
}

impl IasClient {
    pub fn new() -> Self {
        Self {
            https_client: Client::builder().build::<_, hyper::Body>(HttpsConnector::new()),
        }
    }

    pub async fn verify_attestation_evidence(
        &self,
        quote: &[u8],
        api_key: &str,
    ) -> anyhow::Result<AttestationResponse, AttestationError> {
        let uri = format!("{}{}", BASE_URI, REPORT_PATH);
        let quote_base64 = base64::encode(&quote);
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64);

        let req = Request::post(uri)
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", api_key)
            .body(Body::from(body))
            .map_err(|err| AttestationError::Transport(err.to_string()))?;

        let mut resp = self
            .https_client
            .request(req)
            .await
            .map_err(|err| AttestationError::Transport(err.to_string()))?;

        if resp.status().as_u16() != 200 {
            return Err(AttestationError::IAS(resp.status().as_u16()));
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp.body_mut().data().await {
            body.write_all(&chunk.unwrap()).map_err(|_| {
                AttestationError::Transport("Failed to collect HTTP body chunks".to_string())
            })?;
        }

        AttestationResponse::from_response(resp.headers(), body)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    // header
    pub advisory_url: Option<String>,
    pub advisory_ids: Option<String>,
    pub request_id: String,
    // body
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
    // raw bytes
    pub signature: Vec<u8>,
    pub report: Vec<u8>,
}

fn unwrap_header(
    headers: &HeaderMap,
    header_name: &str,
    mandatory: bool,
) -> Result<Option<String>, AttestationError> {
    match headers.get(header_name) {
        Some(val) => Ok(Some(
            val.to_str()
                .map_err(|err| AttestationError::Encoding(err.to_string()))?
                .to_owned(),
        )),
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
    fn from_response(headers: &HeaderMap, body: Vec<u8>) -> anyhow::Result<Self, AttestationError> {
        let report_raw = body.to_owned();

        let body: Value = serde_json::from_slice(&body)
            .map_err(|err| AttestationError::Encoding(err.to_string()))?;

        Ok(Self {
            // header
            advisory_ids: unwrap_header(headers, "advisory-ids", false)?,
            advisory_url: unwrap_header(headers, "advisory-url", false)?,
            request_id: unwrap_header(headers, "request-id", true)?.unwrap(),
            signature: base64::decode(
                &unwrap_header(headers, "x-iasreport-signature", true)?.unwrap(),
            )
            .map_err(|err| AttestationError::Encoding(err.to_string()))?,
            // body
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
            report: report_raw,
        })
    }
}
