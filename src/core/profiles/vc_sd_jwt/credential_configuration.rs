use super::Format;
use crate::core::profiles::claims::CredentialConfigurationClaim;
use crate::profiles::CredentialConfigurationProfile;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_signing_alg_values_supported: Vec<ssi_jwk::Algorithm>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<CredentialConfigurationClaim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    order: Vec<String>,
    vct: String,
}

impl CredentialConfiguration {
    pub fn new(vct: String) -> Self {
        Self {
            vct,
            ..Default::default()
        }
    }

    field_getters_setters![
        pub self [self] ["VC SD-JWT metadata value"] {
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<ssi_jwk::Algorithm>],
            set_order -> order[Vec<String>],
            set_vct -> vct[String],
            set_claims -> claims[Vec<CredentialConfigurationClaim>],
        }
    ];
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::metadata::credential_issuer::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
              "$key$": "SD_JWT_VC_example_in_OpenID4VCI",
              "format": "dc+sd-jwt",
              "scope": "SD_JWT_VC_example_in_OpenID4VCI",
              "cryptographic_binding_methods_supported": [
                "jwk"
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "display": [
                {
                  "name": "IdentityCredential",
                  "logo": {
                    "uri": "https://university.example.edu/public/logo.png",
                    "alt_text": "a square logo of a university"
                  },
                  "locale": "en-US",
                  "background_color": "#12107c",
                  "text_color": "#FFFFFF"
                }
              ],
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "vct": "SD_JWT_VC_example_in_OpenID4VCI",
              "claims": [
                {
                  "path": ["given_name"],
                  "display": [
                    {
                      "name": "Given Name",
                      "locale": "en-US"
                    },
                    {
                      "name": "Vorname",
                      "locale": "de-DE"
                    }
                  ]
                },
                {
                  "path": ["family_name"],
                  "display": [
                    {
                      "name": "Surname",
                      "locale": "en-US"
                    },
                    {
                      "name": "Nachname",
                      "locale": "de-DE"
                    }
                  ]
                },
                {"path": ["email"]},
                {"path": ["phone_number"]},
                {
                  "path": ["address"],
                  "display": [
                    {
                      "name": "Place of residence",
                      "locale": "en-US"
                    },
                    {
                      "name": "Wohnsitz",
                      "locale": "de-DE"
                    }
                  ]
                },
                {"path": ["address", "street_address"]},
                {"path": ["address", "locality"]},
                {"path": ["address", "region"]},
                {"path": ["address", "country"]},
                {"path": ["birthdate"]},
                {"path": ["is_over_18"]},
                {"path": ["is_over_21"]},
                {"path": ["is_over_65"]}
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
