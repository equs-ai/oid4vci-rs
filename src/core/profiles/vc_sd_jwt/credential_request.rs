use serde::{Deserialize, Serialize};

use crate::profiles::CredentialRequestProfile;

use super::CredentialResponse;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest {
    vct: String,
}

impl CredentialRequest {
    pub fn new(vct: String) -> Self {
        Self { vct }
    }
    field_getters_setters![
        pub self [self] ["VC SD-JWT request value"] {
            set_vct -> vct[String],
        }
    ];
}

impl CredentialRequestProfile for CredentialRequest {
    type Response = CredentialResponse;
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::credential::Request;

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "vct": "SD_JWT_VC_example_in_OpenID4VCI",
                "proof": {
                  "proof_type": "jwt",
                  "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlGT3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtjRGpFV183MVNvc0VZIn19.eyJhdWQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNzAxOTYwNDQ0LCJub25jZSI6IkxhclJHU2JtVVBZdFJZTzZCUTR5bjgifQ.-a3EDsxClUB4O3LeDD5DVGEnNMT01FCQW4P6-2-BNBqc_Zxf0Qw4CWayLEpqkAomlkLb9zioZoipdP-jvh1WlA"
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
}
