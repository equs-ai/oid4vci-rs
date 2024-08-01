use openidconnect::{CsrfToken, IssuerUrl, Scope};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::profiles::CredentialOfferProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOffer<CO>
where
    CO: CredentialOfferProfile,
{
    Value {
        #[serde(bound = "CO: CredentialOfferProfile")]
        credential_offer: CredentialOfferParameters<CO>,
    },
    Reference {
        credential_offer_uri: Url,
    },
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferParameters<CO>
where
    CO: CredentialOfferProfile,
{
    credential_issuer: IssuerUrl,
    #[serde(bound = "CO: CredentialOfferProfile")]
    credential_configuration_ids: Vec<CredentialOfferFormat<CO>>,
    grants: Option<CredentialOfferGrants>,
}

impl<CO> CredentialOfferParameters<CO>
where
    CO: CredentialOfferProfile,
{
    pub fn new(
        credential_issuer: IssuerUrl,
        credential_configuration_ids: Vec<CredentialOfferFormat<CO>>,
        grants: Option<CredentialOfferGrants>,
    ) -> Self {
        Self { credential_issuer, credential_configuration_ids, grants }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialOfferFormat<CO>
where
    CO: CredentialOfferProfile,
{
    Reference(Scope),
    #[serde(bound = "CO: CredentialOfferProfile")]
    Value(CO),
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferGrants {
    pub authorization_code: Option<AuthorizationCodeGrant>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizationCodeGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<CsrfToken>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizationCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,
    tx_code: Option<TransactionCode>,
    interval: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionCode {
    length: Option<u64>,
    input_mode: Option<String>,
    description: Option<String>,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::profiles::CoreProfilesOffer;

    use super::*;

    #[test]
    fn example_credential_offer_object() {
        let _: CredentialOfferParameters<CoreProfilesOffer> = serde_json::from_value(json!({
           "credential_issuer": "https://credential-issuer.example.com",
            "credential_configuration_ids": [
                "UniversityDegreeCredential",
                "org.iso.18013.5.1.mDL"
              ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj",
                  "tx_code": {
                    "length": 4,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code that was sent via e-mail"
                  }
                }
           }
        }))
            .unwrap();
    }
}
