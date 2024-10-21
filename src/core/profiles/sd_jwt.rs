use std::collections::HashMap;

use crate::core::profiles::w3c::CredentialSubjectClaims;
use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};
use serde::{Deserialize, Serialize};
use ssi::jwk;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    credential_signing_alg_values_supported: Option<Vec<jwk::Algorithm>>,
    vct: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<HashMap<String, CredentialSubjectClaims>>,
}

impl Metadata {
    pub fn new(vct: String) -> Self {
        Self {
            vct,
            credential_signing_alg_values_supported: None,
            claims: None,
        }
    }
    field_getters_setters![
        pub self [self] ["SD JWT VC metadata value"] {
            set_cryptographic_suites_supported -> credential_signing_alg_values_supported[Option<Vec<jwk::Algorithm>>],
            set_claims -> claims[Option<HashMap<String, CredentialSubjectClaims>>],
        }
    ];

    field_getters! [
     @case ["Metadata vct value"] pub self [self] vct String
    ];
}

impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.vct().to_owned())
    }
}

pub type Offer = String;

impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    pub vct: Option<String>,
    pub credential_configuration_id: Option<String>,
}

impl AuthorizationDetails {
    pub fn new() -> Self {
        Self {
            vct: None,
            credential_configuration_id: None,
        }
    }
    field_getters_setters![
        pub self [self] ["SD JWT VC authorization value"] {
            set_credential_configuration_id -> credential_configuration_id[Option<String>],
            set_vct -> vct[Option<String>],
        }
    ];
}

impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    vct: String,
}

impl Request {
    pub fn new(vct: String) -> Self {
        Self {
            vct,
        }
    }

    field_getters! [
     @case ["Request vct value"] pub self [self] vct String
    ];
}

impl CredentialRequestProfile for Request {
    type Response = Response;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {
    credential: String,
}

impl Response {
    pub fn new(credential: String) -> Self {
        Self { credential }
    }
    field_getters_setters![
        pub self [self] ["JWT VC response value"] {
            set_credential -> credential[String],
        }
    ];
}

impl CredentialResponseProfile for Response {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_metadata() {
        let _: Metadata = serde_json::from_value(json!({
            "vct": "https://issuer.com/credential_1",
            "claims": {
                "address": {
                  "display": [
                    {
                      "locale": "en",
                      "name": "Resident street_address, country, region, locality and postal_code"
                    }
                  ],
                  "mandatory": false
                },
                "administrative_number": {
                  "display": [
                    {
                      "locale": "en",
                      "name": "Alpha-2 country code, representing the nationality of the PID User."
                    }
                  ],
                  "mandatory": false
                },
              },
            "credential_signing_alg_values_supported": [
               "ES256"
            ],
        }))
            .unwrap();
    }

    #[test]
    fn example_authorization() {
        let _: AuthorizationDetails = serde_json::from_value(json!({
            "credential_configuration_id": "UniversityDegreeCredential",
            "vct": "SD_JWT_VC_example_in_OpenID4VCI"
        }))
            .unwrap();
    }
}
