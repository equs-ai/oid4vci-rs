use std::future::Future;

use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AsyncHttpClient, ErrorResponseType, HttpRequest, HttpResponse, StandardErrorResponse,
    SyncHttpClient,
};
use serde::{Deserialize, Serialize};

use crate::types::NonceUrl;
use crate::{
    http_utils::{content_type_has_essence, MIME_TYPE_JSON},
    types::Nonce,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    url: NonceUrl,
}

impl Request {
    pub fn new(url: NonceUrl) -> Self {
        Self { url }
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<Response, RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.nonce_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<Response, RequestError<<C as AsyncHttpClient<'c>>::Error>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    RequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(RequestError::Request)?;

            self.nonce_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestError<http::Error>> {
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .body(vec![])
            .map_err(RequestError::Request)
    }

    fn nonce_response<RE>(self, http_response: HttpResponse) -> Result<Response, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        if !http_response.status().is_success() {
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
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce: Option<Nonce>,
}

impl Response {
    pub fn new(c_nonce: Nonce) -> Self {
        Self { c_nonce: Some(c_nonce) }
    }
    field_getters_setters![
        pub self [self] ["credential response value"] {
            set_nonce -> c_nonce[Option<Nonce>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidRequest,
}
impl ErrorResponseType for ErrorType {}
pub type Error = StandardErrorResponse<ErrorType>;

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn example_credential_deferred_response_object() {
        let _: Response = serde_json::from_value(json!({
            "c_nonce": "wlbQc6pCJp",
        }))
        .unwrap();
    }
}
