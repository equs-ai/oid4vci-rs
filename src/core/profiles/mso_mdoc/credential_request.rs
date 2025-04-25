use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use crate::profiles::CredentialRequestProfile;

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest {
    doctype: DocType,
}

impl CredentialRequest {
    pub fn new(doctype: DocType) -> Self {
        Self { doctype }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL request value"] {
            set_doctype -> doctype[DocType],
        }
    ];
}

impl CredentialRequestProfile for CredentialRequest {
    type Response = super::CredentialResponse;
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{core::profiles::CoreProfilesCredentialRequest, credential::Request};

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "doctype": "org.iso.18013.5.1.mDL",
                "proof": {
                   "proof_type": "jwt",
                   "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: Request<super::CredentialRequest> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "credential_identifier": "org.iso.18013.5.1.mDL",
                "proof": {
                   "proof_type": "jwt",
                   "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: Request<CoreProfilesCredentialRequest> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
