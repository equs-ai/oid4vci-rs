use super::Format;
use crate::{
    core::profiles::claims::CredentialConfigurationClaim, profiles::CredentialConfigurationProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_signing_alg_values_supported: Vec<ssi_jwk::Algorithm>,
    credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<CredentialConfigurationClaim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    order: Vec<String>,
}

impl CredentialConfiguration {
    field_getters_setters![
        pub self [self] ["JWT VC metadata value"] {
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<ssi_jwk::Algorithm>],
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_claims -> claims[Vec<CredentialConfigurationClaim>],
            set_order -> order[Vec<String>],
        }
    ];
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

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

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::metadata::credential_issuer::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
              "$key$": "UniversityDegreeCredential",
              "format": "jwt_vc_json-ld",
              "scope": "UniversityDegree",
              "cryptographic_binding_methods_supported": [
                "did:example"
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "credential_definition": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                  "VerifiableCredential",
                  "UniversityDegreeCredential"
                ]
              },
              "claims": [
                {
                  "path": ["credentialSubject", "given_name"],
                  "display": [
                    {
                      "name": "Given Name",
                      "locale": "en-US"
                    }
                  ]
                },
                {
                  "path": ["credentialSubject", "family_name"],
                  "display": [
                    {
                      "name": "Surname",
                      "locale": "en-US"
                    }
                  ]
                },
                {
                  "path": ["credentialSubject", "degree"]
                },
                {
                  "path": ["credentialSubject", "gpa"],
                  "mandatory": true,
                  "display": [
                    {
                      "name": "GPA"
                    }
                  ]
                }
              ],
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "display": [
                {
                  "name": "University Credential",
                  "locale": "en-US",
                  "logo": {
                    "uri": "https://university.example.edu/public/logo.png",
                    "alt_text": "a square logo of a university"
                  },
                  "background_color": "#12107c",
                  "text_color": "#FFFFFF"
                }
              ]
            }
        );
        let credential_configuration: CredentialConfiguration<super::CredentialConfiguration> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
