use graphene::sgx::{SgxQuote, SgxReport, SgxTargetInfo};
#[cfg(feature = "ias")]
use graphene::Duration;
use std::fs;

const DATA1: &[u8] = &[0xde, 0xad, 0xc0, 0xde];
const DATA2: &[u8] = &[0xca, 0xfe, 0xba, 0xbe];

#[cfg(feature = "ias")]
mod ias {
    use super::*;
    use graphene::sgx::SgxMeasurement;
    use graphene::{AttestationReport, IasClient};
    use std::{convert::TryFrom, env, io};

    fn read_line(prompt: &str) -> Option<String> {
        let mut buf = String::new();
        println!("Enter {}:", prompt);
        io::stdin().read_line(&mut buf).unwrap();
        buf = buf.trim().to_owned();
        if buf.len() > 0 {
            return Some(buf);
        }

        None
    }

    fn read_mr(prompt: &str) -> Option<SgxMeasurement> {
        let mut mr = SgxMeasurement::default();
        let buf = read_line(prompt);

        if let Some(hex) = buf {
            if hex.len() > 0 {
                hex::decode_to_slice(hex, &mut mr).unwrap();
                return Some(mr);
            }
        }

        None
    }

    pub async fn verify_quote() {
        if std::path::Path::new("quote").exists() {
            let quote = fs::read("quote").unwrap();
            let ias_api_key = env::var("IAS_API_KEY");
            match ias_api_key {
                Ok(key) => {
                    let ias = IasClient::develop(&key);
                    let nonce_opt = read_line("IAS nonce");
                    let evidence = ias
                        .verify_attestation_evidence(&quote, nonce_opt.to_owned())
                        .await
                        .unwrap();
                    fs::write("ias-report", &evidence.report).unwrap();
                    fs::write("ias-sig", &evidence.signature).unwrap();

                    let report = AttestationReport::try_from(&evidence).unwrap();

                    let mut verifier = evidence
                        .verifier()
                        //.not_outdated()
                        //.not_debug()
                        .max_age(Duration::seconds(10))
                        .data(DATA1)
                        .data(DATA2);

                    if let Some(nonce) = nonce_opt {
                        verifier = verifier.nonce(&nonce);
                    }

                    if let Some(mr) = read_mr("expected mr_enclave") {
                        verifier = verifier.mr_enclave(mr);
                    }

                    if let Some(mr) = read_mr("expected mr_signer") {
                        verifier = verifier.mr_signer(mr);
                    }

                    if let Some(line) = read_line("expected isv_prod_id") {
                        verifier = verifier.isv_prod_id(line.parse::<u16>().unwrap());
                    }

                    if let Some(line) = read_line("expected isv_svn") {
                        verifier = verifier.isv_svn(line.parse::<u16>().unwrap());
                    }

                    println!(
                        "IAS report: {:?}\nattestation result: {:?}",
                        &report,
                        verifier.check(),
                    );

                    let gid = [0x00, 0x00, 0x0b, 0x39];
                    let sigrl = ias.get_sigrl(&gid).await.unwrap();
                    println!("SigRL for {:?}: {:?}", &gid, &sigrl);
                }
                Err(_) => println!("IAS_API_KEY variable not set"),
            }
        }
    }
}

#[tokio::main]
async fn main() {
    match graphene::is_graphene_enclave() {
        false => {
            println!("Executing outside of Graphene-SGX");
            #[cfg(feature = "ias")]
            ias::verify_quote().await;
        }
        true => {
            println!("Executing in Graphene SGX enclave");

            let target_info = SgxTargetInfo::from_enclave().unwrap();
            println!("\nOur target_info: {:?}", &target_info);

            let report = SgxReport::from_enclave(target_info.as_ref(), DATA1).unwrap();
            println!("\nOur report targeted to ourself: {:?}", &report);

            let quote = SgxQuote::hasher().data(DATA1).data(DATA2).build().unwrap();
            println!("\nOur quote: {:?}", &quote);
            fs::write("quote", quote.as_ref()).unwrap();
        }
    }
}
