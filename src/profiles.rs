use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

pub trait Profile {
    type CredentialConfiguration: CredentialConfigurationProfile;
    type AuthorizationDetailsObject: AuthorizationDetailsObjectProfile;
    type CredentialResponse: CredentialResponseProfile;
}
pub trait CredentialConfigurationProfile: Clone + Debug + DeserializeOwned + Serialize {}
pub trait AuthorizationDetailsObjectProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialResponseProfile: Debug + DeserializeOwned + Serialize {
    type Type: Clone + Debug + DeserializeOwned + Serialize;
}
