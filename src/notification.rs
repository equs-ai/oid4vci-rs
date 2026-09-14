#![allow(clippy::type_complexity)]

use crate::credential::RequestError;
use crate::http_utils::{auth_bearer, MIME_TYPE_JSON};
use crate::types::NotificationUrl;
use oauth2::http::header::{ACCEPT, CONTENT_TYPE};
use oauth2::http::{HeaderValue, Method};
use oauth2::{
    http, AccessToken, AsyncHttpClient, ErrorResponseType, HttpRequest, HttpResponse,
    StandardErrorResponse, SyncHttpClient,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::future::Future;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationRequestEvent {
    #[serde(rename = "credential_accepted")]
    CredentialAccepted,
    #[serde(rename = "credential_failure")]
    CredentialFailure,
    #[serde(rename = "credential_deleted")]
    CredentialDeleted,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NotificationRequest {
    notification_id: String,
    event: NotificationRequestEvent,
    event_description: Option<String>,
}

impl NotificationRequest {
    pub fn new(
        notification_id: String,
        event: NotificationRequestEvent,
        event_description: Option<String>,
    ) -> Self {
        Self {
            notification_id,
            event,
            event_description,
        }
    }

    field_getters_setters![
        pub self [self] ["notification request value"] {
            set_notification_id -> notification_id[String],
            set_event -> event[NotificationRequestEvent],
            set_event_description -> event_description[Option<String>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationErrorCode {
    #[serde(rename = "invalid_notification_id")]
    InvalidNotificationId,
    #[serde(rename = "invalid_notification_request")]
    InvalidNotificationRequest,
}
impl ErrorResponseType for NotificationErrorCode {}
pub type NotificationErrorResponse = StandardErrorResponse<NotificationErrorCode>;

pub struct NotificationRequestBuilder {
    event: NotificationRequest,
    url: NotificationUrl,
    access_token: AccessToken,
}

impl NotificationRequestBuilder {
    pub fn new(
        event: NotificationRequest,
        url: NotificationUrl,
        access_token: AccessToken,
    ) -> Self {
        Self {
            event,
            url,
            access_token,
        }
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<(), RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<(), RequestError<<C as AsyncHttpClient<'c>>::Error>>> + 'c
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

            self.response(http_response)
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
            .body(serde_json::to_vec(&self.event).map_err(|e| RequestError::Other(e.to_string()))?)
            .map_err(RequestError::Request)
    }

    fn response<RE>(self, http_response: HttpResponse) -> Result<(), RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        if http_response.status().is_success() {
            Ok(())
        } else {
            Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_notification_request() {
        let _: NotificationRequest = serde_json::from_value(json!({
            "notification_id": "3fwe98js",
            "event": "credential_accepted"
        }))
        .unwrap();
    }

    #[test]
    fn example_notification_request_with_description() {
        let _: NotificationRequest = serde_json::from_value(json!({
            "notification_id": "3fwe98js",
            "event": "credential_failure",
            "event_description": "Could not store the Credential. Out of storage."
        }))
        .unwrap();
    }

    #[test]
    fn example_notification_error_response() {
        let _: NotificationErrorResponse = serde_json::from_value(json!({
            "error": "invalid_notification_id"
        }))
        .unwrap();
    }
}
