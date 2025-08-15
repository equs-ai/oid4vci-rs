pub mod authorization_detail;
pub mod credential_configuration;
pub mod credential_response;

use serde::{Deserialize, Serialize};

pub const FORMAT_IDENTIFIER: &str = "ldp_vc";
pub use authorization_detail::{AuthorizationDetailsObject, AuthorizationDetailsObjectWithFormat};
pub use credential_configuration::CredentialConfiguration;
pub use credential_response::CredentialResponse;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Format {
    #[default]
    #[serde(rename = "ldp_vc")]
    LdpVc,
}
