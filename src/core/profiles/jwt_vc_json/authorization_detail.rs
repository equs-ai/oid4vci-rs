use serde::{Deserialize, Serialize};

use crate::{
    core::profiles::claims::AuthorizationDetailsObjectClaim,
    profiles::AuthorizationDetailsObjectProfile,
};

use super::Format;

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat {
    format: Format,
    credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObjectWithFormat {
    field_getters_setters![
        pub self [self] ["JWT VC authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_claims -> claims[Vec<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat {}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    credential_definition: CredentialDefinitionWithoutType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObject {
    field_getters_setters![
        pub self [self] ["JWT VC authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionWithoutType],
            set_claims -> claims[Vec<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    r#type: Vec<String>,
}

impl CredentialDefinition {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_type -> r#type[Vec<String>],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutType {}

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
              "format": "jwt_vc_json",
              "credential_definition": {
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
              "credential_configuration_id": "UniversityDegreeCredential",
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
