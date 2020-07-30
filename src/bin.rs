use graphene;
use std::fs;

pub fn main() {
    match graphene::is_graphene_enclave() {
        false => println!("Executing outside of Graphene-SGX"),
        true => {
            println!("Executing in Graphene SGX enclave");
            let target_info = graphene::get_target_info().unwrap();
            println!("\nOur target_info:");
            graphene::display_target_info(&target_info);

            let user_data = &[0xde, 0xad, 0xc0, 0xde];
            let quote = graphene::get_quote(user_data).unwrap();
            println!("\nOur quote:");
            unsafe {
                graphene::display_quote(&quote.quote);
            }
            //println!("Quote signature: {:02x?}", &quote.signature);
            fs::write("quote", graphene::get_quote_bytes(user_data).unwrap()).unwrap();
        }
    }
}
