use graphene::{ias::IasClient, SgxQuote, SgxReport, SgxTargetInfo};
use std::{env, fs};

#[tokio::main]
async fn main() {
    match graphene::is_graphene_enclave() {
        false => {
            println!("Executing outside of Graphene-SGX");
            if std::path::Path::new("quote").exists() {
                let ias = IasClient::new();
                let quote = fs::read("quote").unwrap();
                let ias_api_key = env::var("IAS_API_KEY");
                match ias_api_key {
                    Ok(key) => {
                        let report = ias.verify_attestation_evidence(&quote, &key).await.unwrap();
                        fs::write("ias-report", &report.report).unwrap();
                        println!("IAS report: {:?}", &report);
                        fs::write("ias-sig", &report.signature).unwrap();
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

            let target_info = SgxTargetInfo::new().unwrap();
            println!("\nOur target_info: {}", target_info);

            let user_data = &[0xde, 0xad, 0xc0, 0xde];

            let report = SgxReport::new(&target_info.bytes, user_data).unwrap();
            println!("\nOur report targeted to ourself: {}", report);

            let quote = SgxQuote::new(user_data).unwrap();
            println!("\nOur quote: {}", quote);
            fs::write("quote", &quote.bytes).unwrap();
        }
    }
}
