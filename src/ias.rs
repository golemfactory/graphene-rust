use anyhow::anyhow;
use hyper::body::HttpBody as _;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{client::HttpConnector, Body, Client, Request};
use hyper_tls::HttpsConnector;
use serde_json::Value;
use std::io::Write;

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const SIGRL_PATH: &str = "/attestation/v4/sigrl/";
const REPORT_PATH: &str = "/attestation/v4/report";

pub struct IasClient {
    https_client: Client<HttpsConnector<HttpConnector>>,
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
    ) -> anyhow::Result<AttestationResponse> {
        let uri = format!("{}{}", BASE_URI, REPORT_PATH);
        let quote_base64 = base64::encode(&quote[..]);
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64);

        let req = Request::post(uri)
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", api_key)
            .body(Body::from(body))?;

        dbg!(&req);
        let mut resp = self.https_client.request(req).await?;

        if resp.status().as_u16() != 200 {
            return Err(anyhow!("IAS response: {}", resp.status()));
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp.body_mut().data().await {
            body.write_all(&chunk.unwrap()).unwrap();
        }

        AttestationResponse::from_response(resp.headers(), body)
    }
}

#[derive(Debug)]
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
    // raw
    pub bytes: Vec<u8>,
}

impl AttestationResponse {
    pub fn from_response(headers: &HeaderMap, body: Vec<u8>) -> anyhow::Result<Self> {
        // TODO: get rid of unwrap()
        let bytes = body.to_owned();
        let body: Value = {
            let body = String::from_utf8(body)?;
            serde_json::from_str(&body).unwrap()
        };

        let h = |x: &HeaderValue| -> String { x.to_str().unwrap().to_owned() };
        let b = |x: &str| x.to_owned();
        Ok(Self {
            // header
            advisory_ids: headers.get("advisory-ids").map(h),
            advisory_url: headers.get("advisory-url").map(h),
            request_id: headers.get("request-id").map(h).unwrap(),
            // body
            id: body["id"].as_str().unwrap().to_owned(),
            timestamp: body["timestamp"].as_str().unwrap().to_owned(),
            version: body["version"].as_u64().unwrap() as u16,
            isv_enclave_quote_status: body["isvEnclaveQuoteStatus"].as_str().unwrap().to_owned(),
            isv_enclave_quote_body: body["isvEnclaveQuoteBody"].as_str().unwrap().to_owned(),
            revocation_reason: body["revocationReason"].as_str().map(b),
            pse_manifest_status: body["pseManifestStatus"].as_str().map(b),
            pse_manifest_hash: body["pseManifestHash"].as_str().map(b),
            platform_info_blob: body["platformInfoBlob"].as_str().map(b),
            nonce: body["nonce"].as_str().map(b),
            epid_pseudonym: body["epidPseudonym"].as_str().map(b),
            // raw
            bytes: bytes,
        })
    }
}
