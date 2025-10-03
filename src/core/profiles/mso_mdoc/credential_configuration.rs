use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use super::Format;
use crate::metadata::credential_issuer::DefaultCredentialMetadata;
use crate::profiles::CredentialConfigurationProfile;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    // TODO: Enumerate possible COSE algs
    doctype: DocType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_signing_alg_values_supported: Vec<String>,
    credential_metadata: Option<DefaultCredentialMetadata>,
}

impl CredentialConfiguration {
    pub fn new(doctype: DocType) -> Self {
        Self {
            format: Format::MsoMdoc,
            doctype,
            credential_signing_alg_values_supported: Vec::new(),
            credential_metadata: None,
        }
    }

    field_getters_setters![
        pub self [self] ["ISO mDL metadata value"] {
            set_doctype -> doctype[DocType],
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<String>],
            set_credential_metadata -> credential_metadata[Option<DefaultCredentialMetadata>],
        }
    ];
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

#[cfg(test)]
mod test {
    use crate::metadata::credential_issuer::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = serde_json::json!(
            {
                "$key$": "org.iso.18013.5.1.mDL",
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "cryptographic_binding_methods_supported": [
                    "cose_key"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256", "ES384", "ES512"
                ],
                "credential_metadata": {
                    "display": [
                        {
                            "name": "Mobile Driving License",
                            "locale": "en-US",
                            "logo": {
                                "uri": "https://state.example.org/public/mdl.png",
                                "alt_text": "state mobile driving license"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        },
                        {
                            "name": "モバイル運転免許証",
                            "locale": "ja-JP",
                            "logo": {
                                "uri": "https://state.example.org/public/mdl.png",
                                "alt_text": "米国州発行のモバイル運転免許証"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ],
                    "claims": [
                        {
                            "path": ["org.iso.18013.5.1","given_name"],
                            "display": [
                                {
                                    "name": "Given Name",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "名前",
                                    "locale": "ja-JP"
                                }
                            ]
                        },
                        {
                            "path": ["org.iso.18013.5.1","family_name"],
                            "display": [
                                {
                                    "name": "Surname",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        {
                            "path": ["org.iso.18013.5.1","birth_date"],
                            "mandatory": true
                        },
                        {"path": ["org.iso.18013.5.1.aamva","organ_donor"]}
                    ]
                }
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
