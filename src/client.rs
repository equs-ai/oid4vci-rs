use std::marker::PhantomData;

use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse},
    AccessToken, AuthUrl, AuthorizationCode, ClientId, CodeTokenRequest, ConfigurationError,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, RedirectUrl, StandardRevocableToken,
    TokenUrl,
};

use crate::credential::{DeferredRequest, Request};
use crate::notification::{NotificationRequest, NotificationRequestBuilder};
use crate::types::{NonceUrl, NotificationUrl};
use crate::{
    authorization::AuthorizationRequest,
    credential,
    credential_response_encryption::CredentialResponseEncryptionMetadata,
    metadata::{
        credential_issuer::{CredentialConfiguration, CredentialIssuerMetadataDisplay},
        AuthorizationServerMetadata, CredentialIssuerMetadata,
    },
    nonce, notification,
    pre_authorized_code::PreAuthorizedCodeTokenRequest,
    profiles::Profile,
    pushed_authorization::PushedAuthorizationRequest,
    token,
    types::{CredentialUrl, DeferredCredentialUrl, IssuerUrl, ParUrl, PreAuthorizedCode},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Batch Credential Request are not supported by this issuer")]
    BcrUnsupported,
    #[error("Pushed Authorization Requests are not supported by this issuer")]
    ParUnsupported,
    #[error("Authorization Requests are not supported by this issuer: {0}")]
    AuthUnsupported(ConfigurationError),
    #[error("An error occurred when discovering metadata: {0}")]
    MetadataDiscovery(anyhow::Error),
    #[error("Deferred credential issuance is not supported by this issuer")]
    DeferredIssuanceUnsupported,
    #[error("Notification are not supported by this issuer")]
    NotificationsUnsupported,
}

pub struct Client<C>
where
    C: Profile,
{
    inner: oauth2::Client<
        BasicErrorResponse,
        token::Response,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointMaybeSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    >,
    issuer: IssuerUrl,
    credential_endpoint: CredentialUrl,
    nonce_endpoint: Option<NonceUrl>,
    par_auth_url: Option<ParUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    notification_endpoint: Option<NotificationUrl>,
    credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,
    credential_configurations_supported: Vec<CredentialConfiguration<C::CredentialConfiguration>>,
    display: Option<Vec<CredentialIssuerMetadataDisplay>>,
}

impl<C> Client<C>
where
    C: Profile,
{
    field_getters_setters![
        pub self [self] ["client configuration value"] {
            set_issuer -> issuer[IssuerUrl],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryptionMetadata>],
            set_credential_configurations_supported -> credential_configurations_supported[Vec<CredentialConfiguration<C::CredentialConfiguration>>],
            set_display -> display[Option<Vec<CredentialIssuerMetadataDisplay>>],
        }
    ];

    pub fn from_issuer_metadata(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        credential_issuer_metadata: CredentialIssuerMetadata<C::CredentialConfiguration>,
        authorization_metadata: AuthorizationServerMetadata,
    ) -> Self {
        let inner = Self::new_inner_client(
            client_id,
            redirect_uri,
            authorization_metadata.authorization_endpoint().cloned(),
            authorization_metadata.token_endpoint().clone(),
        );

        Self {
            inner,
            issuer: credential_issuer_metadata.credential_issuer().clone(),
            credential_endpoint: credential_issuer_metadata.credential_endpoint().clone(),
            nonce_endpoint: credential_issuer_metadata.nonce_endpoint().cloned(),
            par_auth_url: authorization_metadata
                .pushed_authorization_request_endpoint()
                .cloned(),
            deferred_credential_endpoint: credential_issuer_metadata
                .deferred_credential_endpoint()
                .cloned(),
            notification_endpoint: credential_issuer_metadata.notification_endpoint().cloned(),
            credential_response_encryption: credential_issuer_metadata
                .credential_response_encryption()
                .cloned(),
            credential_configurations_supported: credential_issuer_metadata
                .credential_configurations_supported()
                .clone(),
            display: credential_issuer_metadata.display().cloned(),
        }
    }

    pub fn pushed_authorization_request<S>(
        &self,
        state_fn: S,
    ) -> Result<PushedAuthorizationRequest, Error>
    where
        S: FnOnce() -> CsrfToken,
    {
        let Some(par_url) = self.par_auth_url.as_ref() else {
            return Err(Error::ParUnsupported);
        };
        let inner = self.authorize_url(state_fn)?;
        Ok(PushedAuthorizationRequest::new(
            inner,
            par_url.clone(),
            self.inner
                .auth_uri()
                .cloned()
                .ok_or(Error::AuthUnsupported(ConfigurationError::MissingUrl(
                    "authorization",
                )))?,
        ))
    }

    pub fn authorize_url<S>(&self, state_fn: S) -> Result<AuthorizationRequest, Error>
    where
        S: FnOnce() -> CsrfToken,
    {
        let inner = self
            .inner
            .authorize_url(state_fn)
            .map_err(Error::AuthUnsupported)?;
        Ok(AuthorizationRequest::new(inner))
    }

    pub fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> CodeTokenRequest<'_, BasicErrorResponse, token::Response> {
        self.inner.exchange_code(code)
    }

    pub fn exchange_pre_authorized_code(
        &self,
        pre_authorized_code: PreAuthorizedCode,
    ) -> PreAuthorizedCodeTokenRequest<'_, BasicErrorResponse, token::Response> {
        PreAuthorizedCodeTokenRequest {
            auth_type: self.inner.auth_type(),
            client_id: Some(self.inner.client_id()),
            client_secret: None,
            code: pre_authorized_code,
            extra_params: Vec::new(),
            token_url: self.inner.token_uri().clone(),
            tx_code: None,
            _phantom: PhantomData,
        }
    }

    pub fn request_credential(
        &self,
        access_token: AccessToken,
        credential_id: credential::CredentialId,
    ) -> credential::RequestBuilder<Request> {
        let body = Request::new(credential_id);
        credential::RequestBuilder::new(body, self.credential_endpoint().to_string(), access_token)
    }

    pub fn request_deferred_credential(
        &self,
        access_token: AccessToken,
        transaction_id: String,
    ) -> Result<credential::RequestBuilder<DeferredRequest>, Error> {
        let request = DeferredRequest::new(transaction_id);
        self.deferred_credential_endpoint
            .as_ref()
            .map(|endpoint| {
                credential::RequestBuilder::new(request, endpoint.to_string(), access_token)
            })
            .ok_or(Error::DeferredIssuanceUnsupported)
    }

    pub fn request_nonce(&self) -> Option<nonce::Request> {
        if let Some(nonce_endpoint) = &self.nonce_endpoint {
            return Some(nonce::Request::new(nonce_endpoint.to_owned()));
        }

        None
    }

    pub fn send_notification(
        &self,
        access_token: AccessToken,
        notification: NotificationRequest,
    ) -> Result<NotificationRequestBuilder, Error> {
        self.notification_endpoint
            .as_ref()
            .map(|endpoint| {
                NotificationRequestBuilder::new(notification, endpoint.to_owned(), access_token)
            })
            .ok_or(Error::NotificationsUnsupported)
    }

    fn new_inner_client(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        auth_url: Option<AuthUrl>,
        token_url: TokenUrl,
    ) -> oauth2::Client<
        BasicErrorResponse,
        token::Response,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointMaybeSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    > {
        oauth2::Client::new(client_id)
            .set_redirect_uri(redirect_uri)
            .set_auth_uri_option(auth_url)
            .set_token_uri(token_url)
    }
}
