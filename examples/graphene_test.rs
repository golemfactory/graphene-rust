use graphene::ias::{AttestationReport, IasClient};
use graphene::sgx::{SgxMeasurement, SgxQuote, SgxReport, SgxTargetInfo};
use std::{convert::TryFrom, env, fs, io};

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

#[tokio::main]
async fn main() {
    let user_data = &[0xde, 0xad, 0xc0, 0xde];
    match graphene::is_graphene_enclave() {
        false => {
            println!("Executing outside of Graphene-SGX");
            if std::path::Path::new("quote").exists() {
                let ias = IasClient::new(false);
                let quote = fs::read("quote").unwrap();
                let ias_api_key = env::var("IAS_API_KEY");
                match ias_api_key {
                    Ok(key) => {
                        let nonce = read_line("IAS nonce");
                        let response = ias
                            .verify_attestation_evidence(&quote, &key, nonce.clone())
                            .await
                            .unwrap();
                        fs::write("ias-report", &response.report).unwrap();
                        fs::write("ias-sig", &response.signature).unwrap();
                        let report = AttestationReport::try_from(response).unwrap();

                        println!(
                            "IAS report: {:?}, verify: {}",
                            &report,
                            report
                                .verify(
                                    true, // allow_outdated
                                    nonce,
                                    Some(user_data),
                                    read_mr("expected mr_enclave"),
                                    read_mr("expected mr_signer"),
                                    read_line("expected isv_prod_id")
                                        .map(|x| x.parse::<u16>().unwrap()),
                                    read_line("expected isv_svn")
                                        .map(|x| x.parse::<u16>().unwrap()),
                                )
                                .unwrap()
                        );
                        let gid = [0x00, 0x00, 0x0b, 0x39];
                        let sigrl = ias.get_sigrl(&gid, &key).await.unwrap();
                        println!("SigRL for {:?}: {:?}", &gid, &sigrl);
                    }
                    Err(_) => println!("IAS_API_KEY variable not set"),
                }
            }
        }
        true => {
            println!("Executing in Graphene SGX enclave");

            let target_info = SgxTargetInfo::from_enclave().unwrap();
            println!("\nOur target_info: {:?}", &target_info);

            let report = SgxReport::from_enclave(target_info.as_ref(), user_data).unwrap();
            println!("\nOur report targeted to ourself: {:?}", &report);

            let quote = SgxQuote::from_enclave(user_data).unwrap();
            println!("\nOur quote: {:?}", &quote);
            fs::write("quote", quote.as_ref()).unwrap();
        }
    }
}
