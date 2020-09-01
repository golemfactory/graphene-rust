#[macro_use]
mod macros;

mod graphene;
mod ias;
pub mod sgx;

pub use crate::graphene::{
    get_quote, get_report, get_target_info, is_graphene_enclave, set_protected_files_key,
};

pub use ias::{AttestationReport, AttestationResponse};

#[cfg(feature = "ias")]
pub use ias::online::IasClient;
