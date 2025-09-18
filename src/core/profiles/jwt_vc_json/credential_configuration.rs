use super::Format;
use crate::metadata::credential_issuer::DefaultCredentialMetadata;
use crate::profiles::CredentialConfigurationProfile;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_signing_alg_values_supported: Vec<ssi_jwk::Algorithm>,
    credential_definition: CredentialDefinition,
    credential_metadata: Option<DefaultCredentialMetadata>,
}

impl CredentialConfiguration {
    field_getters_setters![
        pub self [self] ["JWT VC credential configuration value"] {
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<ssi_jwk::Algorithm>],
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_credential_metadata -> credential_metadata[Option<DefaultCredentialMetadata>],
        }
    ];
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

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

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::metadata::credential_issuer::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "$key$": "UniversityDegreeCredential",
                "format": "jwt_vc_json",
                "scope": "UniversityDegree",
                "cryptographic_binding_methods_supported": [
                    "did:example"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                    ]
                },
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": [
                            "ES256"
                        ]
                    }
                },
                "credential_metadata": {
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
                },
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
