use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use ssi::jwk;

use crate::core::profiles::w3c::CredentialSubjectClaims;
use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinitionSdJwt {
    r#type: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<HashMap<String, CredentialSubjectClaims>>,
}

impl CredentialDefinitionSdJwt {
    pub fn new(r#type: serde_json::Value) -> Self {
        Self {
            r#type,
            claims: None,
        }
    }

    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_type -> r#type[serde_json::Value],
            set_claims -> claims[Option<HashMap<String, CredentialSubjectClaims>>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    credential_signing_alg_values_supported: Option<Vec<jwk::Algorithm>>,
    credential_definition: CredentialDefinitionSdJwt,
}

impl Metadata {
    pub fn new(credential_definition: CredentialDefinitionSdJwt) -> Self {
        Self {
            credential_signing_alg_values_supported: None,
            credential_definition,
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC metadata value"] {
            set_cryptographic_suites_supported -> credential_signing_alg_values_supported[Option<Vec<jwk::Algorithm>>],
            set_credential_definition -> credential_definition[CredentialDefinitionSdJwt],
        }
    ];
}

impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request {}
    }
}

pub type Offer = String;

impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    vct: Option<String>,
    credential_configuration_id: Option<String>,
}

impl AuthorizationDetails {
    pub fn new() -> Self {
        Self {
            vct: None,
            credential_configuration_id: None,
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC authorization value"] {
            set_credential_configuration_id -> credential_configuration_id[Option<String>],
            set_vct -> vct[Option<String>],
        }
    ];
}

impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {}

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
            "credential_definition": {
                "type": ["test"],
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
                }
            }
        ))
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
