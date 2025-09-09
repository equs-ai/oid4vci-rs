use std::future::Future;

use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, ErrorResponseType, HttpRequest, HttpResponse,
    StandardErrorResponse, SyncHttpClient,
};
use serde::{Deserialize, Serialize};

use crate::{
    credential_response_encryption::CredentialResponseEncryption,
    http_utils::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
    profiles::CredentialResponseProfile,
    types::{CredentialConfigurationId, CredentialIdentifier, CredentialUrl},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    #[serde(flatten)]
    pub credential_id: CredentialId,
    #[serde(skip_serializing_if = "Option::is_none")]
    proofs: Option<Proofs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_response_encryption: Option<CredentialResponseEncryption>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CredentialId {
    #[serde(rename = "credential_identifier")]
    CredentialIdentifier(CredentialIdentifier),
    #[serde(rename = "credential_configuration_id")]
    CredentialConfigurationId(CredentialConfigurationId),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Proofs {
    #[serde(rename = "jwt")]
    Jwt(Vec<String>),
    #[serde(rename = "di_vp")]
    DiVp(Vec<serde_json::Value>),
}

impl Proofs {
    pub fn len(&self) -> usize {
        match self {
            Proofs::Jwt(proofs) => proofs.len(),
            Proofs::DiVp(proofs) => proofs.len(),
        }
    }
}

impl Request {
    pub(crate) fn new(credential_id: CredentialId) -> Self {
        Self {
            credential_id,
            proofs: None,
            credential_response_encryption: None,
        }
    }

    field_getters_setters![
        pub self [self] ["credential request value"] {
            set_proofs -> proofs[Option<Proofs>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryption>],
        }
    ];
}

pub struct RequestBuilder {
    body: Request,
    url: CredentialUrl,
    access_token: AccessToken,
}

impl RequestBuilder {
    pub(crate) fn new(body: Request, url: CredentialUrl, access_token: AccessToken) -> Self {
        Self {
            body,
            url,
            access_token,
        }
    }

    field_getters_setters![
        pub self [self.body] ["credential request value"] {
            set_proofs -> proofs[Option<Proofs>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryption>],
        }
    ];

    pub fn request<C, CR>(
        self,
        http_client: &C,
    ) -> Result<Response<CR>, RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
        CR: CredentialResponseProfile,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C, CR>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<Response<CR>, RequestError<<C as AsyncHttpClient<'c>>::Error>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        CR: CredentialResponseProfile,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    RequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(RequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(serde_json::to_vec(&self.body).map_err(|e| RequestError::Other(e.to_string()))?)
            .map_err(RequestError::Request)
    }

    fn credential_response<RE, CR>(
        self,
        http_response: HttpResponse,
    ) -> Result<Response<CR>, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
        CR: CredentialResponseProfile,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers()
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    http_response.body(),
                ))
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError<RE>
where
    RE: std::error::Error + 'static,
{
    #[error("Failed to parse server response")]
    Parse(#[source] serde_path_to_error::Error<serde_json::Error>),
    #[error("Request failed")]
    Request(#[source] RE),
    #[error("Server returned invalid response: {2}")]
    Response(StatusCode, Vec<u8>, String),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(flatten, bound = "CR: CredentialResponseProfile")]
    response_kind: ResponseEnum<CR>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_id: Option<String>,
}

impl<CR> Response<CR>
where
    CR: CredentialResponseProfile,
{
    pub fn new(response_kind: ResponseEnum<CR>) -> Self {
        Self {
            response_kind,
            notification_id: None,
        }
    }
    field_getters_setters![
        pub self [self] ["credential response value"] {
            set_response_kind -> response_kind[ResponseEnum<CR>],
            set_notification_id -> notification_id[Option<String>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseEnum<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    Immediate {
        credentials: Vec<CR::Type>,
    },
    Deferred {
        transaction_id: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidCredentialRequest,
    UnknownCredentialConfiguration,
    UnknownCredentialIdentifier,
    InvalidProof,
    InvalidNonce,
    InvalidEncryptionParameters,
    CredentialRequestDenied,
    /// Authorization error: invalid_request
    /// [RFC6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)
    InvalidRequest,
    /// Authorization error: invalid_token
    /// [RFC6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)
    InvalidToken,
    /// Authorization error: insufficient_scope
    /// [RFC6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)
    InsufficientScope,
}
impl ErrorResponseType for ErrorType {}
pub type Error = StandardErrorResponse<ErrorType>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeferredRequest {
    transaction_id: String,
}

#[cfg(test)]
mod test {
    use assert_json_diff::assert_json_eq;
    use rstest::*;
    use serde_json::json;

    use crate::core::profiles::CoreProfilesCredentialResponse;

    use super::*;

    #[rstest]
    #[case::with_credential_configuration_id(json!({
      "credential_configuration_id": "org.iso.18013.5.1.mDL",
      "proofs": {
        "jwt": [
          "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8x
           IiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
        ]
      }
    }))]
    #[case::with_credential_identifier_multiple_proofs(json!({
      "credential_identifier": "CivilEngineeringDegree-2023",
      "proofs": {
        "jwt": [
          "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0
           eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlG
           T3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtj
           RGpFV183MVNvc0VZIn19",
          "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8x
           IiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
        ]
      }
    }))]
    #[case::with_di_vp_proof(json!({
      "credential_identifier": "CivilEngineeringDegree-2023",
      "proofs": {
        "di_vp": [
          {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": [
              "VerifiablePresentation"
            ],
            "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
            "proof": [
              {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-2022",
                "proofPurpose": "authentication",
                "verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mq
                 h5XPvLsrPsro#z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                "created": "2023-03-01T14:56:29.280619Z",
                "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
                "domain": "did:web:audience.company.com",
                "proofValue": "z5hrbHzZiqXHNpLq6i7zePEUcUzEbZKmWfNQzXcUXUrqF7bykQ7A
                 CiWFyZdT2HcptF1zd1t7NhfQSdqrbPEjZceg7"
              }
            ]
          }
        ]
      }
    }))]
    fn spec_example_roundtrip(#[case] example: serde_json::Value) {
        let parsed: Request = serde_json::from_value(example.clone()).unwrap();
        let serialized = serde_json::to_value(parsed).unwrap();
        assert_json_eq!(example, serialized);
    }

    #[test]
    fn example_credential_response_object() {
        let resp: Response<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
            "credentials": [
                {"credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"},
                {"credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"}
            ],
            "notification_id": "1",
        }))
        .unwrap();

        if let ResponseEnum::Immediate { credentials } = resp.response_kind {
            assert_eq!(credentials.len(), 2);
        } else {
            panic!("Unexpected response type");
        }
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let resp: Response<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
            "transaction_id": "8xLOxBtZp8",
        }))
        .unwrap();

        if let ResponseEnum::Deferred { transaction_id } = resp.response_kind {
            assert_eq!(transaction_id.unwrap().as_str(), "8xLOxBtZp8");
        } else {
            panic!("Unexpected response type");
        }
    }

    #[test]
    fn example_error() {
        let _: Error = serde_json::from_value(json!({
            "error": "invalid_proof",
            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
        }))
            .unwrap();
    }

    #[test]
    fn example_deferred_request() {
        let _: DeferredRequest = serde_json::from_value(json!({
            "transaction_id":"8xLOxBtZp8"
        }))
        .unwrap();
    }
}
