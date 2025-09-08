use crate::types::LanguageTag;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct AuthorizationDetailsObjectClaim {
    path: ClaimsPath,
    #[serde(default, skip_serializing_if = "is_false")]
    mandatory: bool,
}

impl AuthorizationDetailsObjectClaim {
    field_getters_setters![
        pub self [self] ["Authorization Detail"] {
            set_path -> path[ClaimsPath],
            set_mandatory -> mandatory[bool],
        }
    ];
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CredentialConfigurationClaim {
    #[serde(default, skip_serializing_if = "is_false")]
    mandatory: bool,
    path: ClaimsPath,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    display: Vec<ClaimDisplay>,
}

fn is_false(b: &bool) -> bool {
    !b
}

impl CredentialConfigurationClaim {
    field_getters_setters![
        pub self [self] ["Credential configuration claim"] {
            set_mandatory -> mandatory[bool],
            set_path -> path[ClaimsPath],
            set_display -> display[Vec<ClaimDisplay>],
        }
    ];
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClaimDisplay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locale: Option<LanguageTag>,
}

impl ClaimDisplay {
    field_getters_setters![
        pub self [self] ["Claim display"] {
            set_name -> name[Option<String>],
            set_locale -> locale[Option<LanguageTag>],
        } 
    ];
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde_as]
pub struct ClaimsPath(#[serde_as(deserialize_as = "DefaultOnNull")] pub Vec<ClaimPathPointer>);

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ClaimPathPointer {
    ElementKey(String),
    ElementIndex(usize),
    AllElements,
}

impl Default for ClaimPathPointer {
    fn default() -> Self {
        ClaimPathPointer::AllElements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clims_path_serialization() {
        let path = ClaimsPath(vec![
            ClaimPathPointer::ElementKey("KEY".to_owned()),
            ClaimPathPointer::AllElements,
            ClaimPathPointer::ElementIndex(13),
        ]);
        let expected = json!(["KEY", null, 13]);
        let actual = serde_json::to_value(&path).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn claims_path_deserialization() {
        let expected = ClaimsPath(vec![
            ClaimPathPointer::ElementKey("KEY".to_owned()),
            ClaimPathPointer::AllElements,
            ClaimPathPointer::ElementIndex(13),
        ]);
        let actual: ClaimsPath = serde_json::from_value(json!(["KEY", null, 13])).unwrap();
        assert_eq!(expected, actual);
    }
}
