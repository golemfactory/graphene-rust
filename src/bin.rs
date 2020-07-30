use graphene::{SgxQuote, SgxReport, SgxTargetInfo};
use std::fs;

pub fn main() {
    match graphene::is_graphene_enclave() {
        false => println!("Executing outside of Graphene-SGX"),
        true => {
            println!("Executing in Graphene SGX enclave");

            let target_info = SgxTargetInfo::new().unwrap();
            println!("\nOur target_info:");
            target_info.display();

            let user_data = &[0xde, 0xad, 0xc0, 0xde];

            let report = SgxReport::new(&target_info.bytes, user_data).unwrap();
            println!("\nOur report targeted to ourself:");
            report.display();

            let quote = SgxQuote::new(user_data).unwrap();
            println!("\nOur quote:");
            unsafe {
                quote.display();
            }
            //println!("Quote signature: {:02x?}", &quote.signature);
            fs::write("quote", quote.bytes).unwrap();
        }
    }
}
