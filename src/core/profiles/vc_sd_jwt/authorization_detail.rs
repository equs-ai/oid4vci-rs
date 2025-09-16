use serde::{Deserialize, Serialize};

use crate::core::profiles::claims::AuthorizationDetailsObjectClaim;
use crate::profiles::AuthorizationDetailsObjectProfile;

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    vct: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObject {
    field_getters_setters![
        pub self [self] ["VC SD-JWT authorization detail value"] {
            set_vct -> vct[String],
            set_claims -> claims[Vec<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::authorization::AuthorizationDetailsObject;
    use crate::core::profiles::CoreProfilesAuthorizationDetailsObject;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "type": "openid_credential",
                "credential_configuration_id": "UniversityDegreeCredential",
                "vct": "SD_JWT_VC_example_in_OpenID4VCI"
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
