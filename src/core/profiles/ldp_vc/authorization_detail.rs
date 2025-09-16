use std::fmt::Debug;

use crate::core::profiles::claims::AuthorizationDetailsObjectClaim;
use crate::profiles::AuthorizationDetailsObjectProfile;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    claims: Vec<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObject {
    field_getters_setters![
        pub self [self] ["authorization detail value"] {
            set_claims -> claims[Vec<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        authorization::AuthorizationDetailsObject,
        core::profiles::CoreProfilesAuthorizationDetailsObject,
    };

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
