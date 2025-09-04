use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::profiles::ldp_vc::Format;
use crate::{
    core::profiles::claims::AuthorizationDetailsObjectClaim,
    profiles::AuthorizationDetailsObjectProfile,
};

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat {
    format: Format,
    credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObjectWithFormat {
    field_getters_setters![
        pub self [self] ["authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_claims -> claims[Vec<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat {}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    credential_definition: CredentialDefinitionWithoutContext,
}

impl AuthorizationDetailsObject {
    field_getters_setters![
        pub self [self] ["authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionWithoutContext],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    #[serde(rename = "@context")]
    context: Vec<Value>,
    r#type: Vec<String>,
}

impl CredentialDefinition {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_context -> context[Vec<Value>],
            set_type -> r#type[Vec<String>],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutContext {}

impl CredentialDefinitionWithoutContext {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        authorization::AuthorizationDetailsObject,
        core::profiles::CoreProfilesAuthorizationDetailsObject,
    };

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
          {
            "type": "openid_credential",
            "format": "ldp_vc",
            "credential_definition": {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
              ],
              "type": [
                "UniversityDegreeCredential"
              ],
            },
            "claims": [
              {"path": ["credentialSubject", "given_name"]},
              {"path": ["credentialSubject", "family_name"]},
              {"path": ["credentialSubject", "degree"]}
            ]
          }
        );

        let authorization_detail: AuthorizationDetailsObject<
            super::AuthorizationDetailsObjectWithFormat,
        > = serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
            &serde_json::to_string(&expected_json).unwrap(),
        ))
        .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }

    #[test]
    fn roundtrip() {
        let expected_json = json!(
          {
            "type": "openid_credential",
            "credential_configuration_id": "UniversityDegree_LDP_VC",
            "claims": [
              {"path": ["credentialSubject", "given_name"]},
              {"path": ["credentialSubject", "family_name"]},
              {"path": ["credentialSubject", "degree"]}
            ]
          }
        );

        let authorization_detail: AuthorizationDetailsObject<
            CoreProfilesAuthorizationDetailsObject,
        > = serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
            &serde_json::to_string(&expected_json).unwrap(),
        ))
        .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
