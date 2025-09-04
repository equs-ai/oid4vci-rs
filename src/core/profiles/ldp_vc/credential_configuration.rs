use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::profiles::ldp_vc::Format;
use crate::{
    core::profiles::claims::CredentialConfigurationClaim, profiles::CredentialConfigurationProfile,
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    // TODO: Enumerate types from LD Suite Registry:
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.1.2.2-1
    credential_signing_alg_values_supported: Vec<String>,
    credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    order: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<CredentialConfigurationClaim>,
}

impl CredentialConfiguration {
    field_getters_setters![
        pub self [self] ["metadata value"] {
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<String>],
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_order -> order[Vec<String>],
            set_claims -> claims[Vec<CredentialConfigurationClaim>],
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
                "$key$": "UniversityDegreeCredential_LDP_VC",
                "format": "ldp_vc",
                "cryptographic_binding_methods_supported": [
                  "did:example"
                ],
                "credential_signing_alg_values_supported": [
                  "Ed25519Signature2018"
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
