use serde::{Deserialize, Serialize};
use ssi::claims::JwsBuf;

use crate::profiles::CredentialResponseProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialResponse;

impl CredentialResponseProfile for CredentialResponse {
    type Type = JwsBuf;
}
