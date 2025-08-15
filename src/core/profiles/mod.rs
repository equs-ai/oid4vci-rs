use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    profiles::{
        AuthorizationDetailsObjectProfile, CredentialConfigurationProfile,
        CredentialResponseProfile, Profile,
    },
    types::CredentialConfigurationId,
};

pub mod claims;
pub mod jwt_vc_json;
pub mod jwt_vc_json_ld;
pub mod ldp_vc;
pub mod mso_mdoc;
pub mod vc_sd_jwt;

pub struct CoreProfiles;
impl Profile for CoreProfiles {
    type CredentialConfiguration = CoreProfilesCredentialConfiguration;
    type AuthorizationDetailsObject = CoreProfilesAuthorizationDetailsObject;
    type CredentialResponse = CoreProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesCredentialConfiguration {
    JwtVcJson(jwt_vc_json::CredentialConfiguration),
    JwtVcJsonLd(jwt_vc_json_ld::CredentialConfiguration),
    LdpVc(ldp_vc::CredentialConfiguration),
    MsoMdoc(mso_mdoc::CredentialConfiguration),
    VcSdJwt(vc_sd_jwt::CredentialConfiguration),
}

impl CredentialConfigurationProfile for CoreProfilesCredentialConfiguration {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesAuthorizationDetailsObject {
    WithFormat {
        #[serde(flatten)]
        inner: AuthorizationDetailsObjectWithFormat,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "credential_identifier"
        )]
        _credential_identifier: (),
    },
    WithIdAndUnresolvedProfile {
        credential_configuration_id: CredentialConfigurationId,
        #[serde(flatten)]
        inner: HashMap<String, Value>,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
    #[serde(skip_deserializing)]
    WithId {
        credential_configuration_id: CredentialConfigurationId,
        #[serde(flatten)]
        inner: AuthorizationDetailsObjectWithCredentialConfigurationId,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationDetailsObjectWithFormat {
    JwtVcJson(jwt_vc_json::AuthorizationDetailsObjectWithFormat),
    JwtVcJsonLd(jwt_vc_json_ld::AuthorizationDetailsObjectWithFormat),
    LdpVc(ldp_vc::AuthorizationDetailsObjectWithFormat),
    MsoMdoc(mso_mdoc::AuthorizationDetailsObjectWithFormat),
    VcSdJwt(vc_sd_jwt::AuthorizationDetailsObjectWithFormat),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationDetailsObjectWithCredentialConfigurationId {
    VcSdJwt(vc_sd_jwt::AuthorizationDetailsObject),
    LdpVc(ldp_vc::AuthorizationDetailsObject),
    MsoMdoc(mso_mdoc::AuthorizationDetailsObject),
    JwtVcJson(jwt_vc_json::AuthorizationDetailsObject),
    JwtVcJsonLd(jwt_vc_json_ld::AuthorizationDetailsObject),
}

impl AuthorizationDetailsObjectProfile for CoreProfilesAuthorizationDetailsObject {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoreProfilesCredentialResponse;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesCredentialResponseType {
    VcSdJwt {
        credential: <vc_sd_jwt::CredentialResponse as CredentialResponseProfile>::Type,
    },
    LdpVc {
        credential: <ldp_vc::CredentialResponse as CredentialResponseProfile>::Type,
    },
    MsoMdoc {
        credential: <mso_mdoc::CredentialResponse as CredentialResponseProfile>::Type,
    },
    JwtVcJson {
        credential: <jwt_vc_json::CredentialResponse as CredentialResponseProfile>::Type,
    },
    JwtVcJsonLd {
        credential: <jwt_vc_json_ld::CredentialResponse as CredentialResponseProfile>::Type,
    },
}

impl CredentialResponseProfile for CoreProfilesCredentialResponse {
    type Type = CoreProfilesCredentialResponseType;
}
