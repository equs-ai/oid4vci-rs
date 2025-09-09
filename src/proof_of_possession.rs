use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::{
    jws::{self, Header},
    jwt,
};
use ssi_dids_core::DIDURLBuf;
use ssi_jwk::{Algorithm, JWKResolver, JWK};
use std::ops::{Add, Sub};
use time::{Duration, OffsetDateTime};

use crate::types::Nonce;

const JWS_TYPE: &str = "openid4vci-proof+jwt";

pub type ProofSigningAlgValuesSupported = Vec<ssi_jwk::Algorithm>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyProofTypesSupported {
    #[serde(rename = "$key$")]
    pub key: KeyProofType,
    pub proof_signing_alg_values_supported: ProofSigningAlgValuesSupported,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Hash, Eq)]
pub enum KeyProofType {
    #[serde(rename = "jwt")]
    Jwt,
    #[serde(rename = "di_vp")]
    DiVp,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "proof_type")]
pub enum Proof {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    #[serde(rename = "di_vp")]
    DiVp { di_vp: Value },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofOfPossessionBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iss")]
    pub issuer: Option<String>,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "nbf")]
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    #[serde(default)]
    pub not_before: Option<OffsetDateTime>,
    #[serde(rename = "iat")]
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub issued_at: Option<OffsetDateTime>,
    #[serde(rename = "exp", with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
}

#[derive(Debug, Clone)]
pub struct ProofOfPossession {
    pub body: ProofOfPossessionBody,
    pub controller: ProofOfPossessionController,
}

#[derive(Debug, Clone)]
pub struct ProofOfPossessionController {
    pub vm: Option<DIDURLBuf>,
    pub jwk: JWK,
}

pub struct ProofOfPossessionParams {
    pub audience: String,
    pub issuer: Option<String>,
    pub nonce: Option<Nonce>,
    pub controller: ProofOfPossessionController,
    pub not_before: Option<ProofOfPossessionNotBefore>,
}

/// Configures how Not Before claim (see [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)) must be specified.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProofOfPossessionNotBefore {
    /// Sets nbf the same as iat.
    AsIssuedAt,
    /// Sets nbf to provided timestamp.
    Fixed(OffsetDateTime),
    /// Sets nbf with a given delay from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00;
    ///     `delay` is 5 min;
    ///     then `nbf` will be 10:05:00.
    Delay(Duration),
    /// Sets nbf with a given leeway from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00
    ///     `leeway` is 5 min
    ///     then `nbf` will be 9:55:00
    Leeway(Duration),
}

impl ProofOfPossessionNotBefore {
    pub(crate) fn gen_relative_to(&self, issued_at: &OffsetDateTime) -> OffsetDateTime {
        match self {
            ProofOfPossessionNotBefore::AsIssuedAt => issued_at.clone(),
            ProofOfPossessionNotBefore::Fixed(fixed) => fixed.clone(),
            ProofOfPossessionNotBefore::Delay(delay) => issued_at.add(delay.to_owned()),
            ProofOfPossessionNotBefore::Leeway(leeway) => issued_at.sub(leeway.to_owned()),
        }
    }
}

pub struct ProofOfPossessionVerificationParams {
    pub audience: String,
    pub issuer: Option<String>,
    pub nonce: Option<Nonce>,
    pub controller_did: Option<DIDURLBuf>,
    pub controller_jwk: Option<JWK>,
    /// Slack in nbf validation to deal with clock synchronisation issues.
    pub nbf_tolerance: Option<Duration>,
    /// Slack in exp validation to deal with clock synchronisation issues.
    pub exp_tolerance: Option<Duration>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerificationError {
    #[error("proof of possession is not yet valid")]
    NotYetValid,
    #[error("proof of possession is expired")]
    Expired,
    #[error("proof of possession issuer does not match, expected `{expected}`, found `{actual}`")]
    InvalidIssuer { actual: String, expected: String },
    #[error(
        "proof of possession audience does not match, expected `{expected}`, found `{actual}`"
    )]
    InvalidAudience { actual: String, expected: String },
    #[error("proof of possession JWK does not match")]
    InvalidJWK,
    #[error("proof of possession DID does not match, expected `{expected}`, found `{actual}`")]
    InvalidDID { actual: String, expected: String },
    #[error("proof of possession Nonce does not match")]
    InvalidNonce,
}

#[derive(thiserror::Error, Debug)]
pub enum ConversionError {
    #[error(transparent)]
    SerializationError(#[from] serde_json::Error),
    #[error(transparent)]
    SigningError(#[from] ssi_claims::jws::Error),
    #[error("Unable to select JWT algorithm, please specify in JWK")]
    MissingJWKAlg,
}

#[derive(thiserror::Error, Debug)]
pub enum ParsingError {
    #[error(transparent)]
    InvalidJWS(#[from] ssi_claims::jws::Error),
    #[error("JWS type header is invalid, expected `{expected}`, found `{actual}`")]
    InvalidJWSType { actual: String, expected: String },
    #[error("JWS does not specify an algorithm")]
    MissingJWSAlg,
    #[error("Missing key parameter, exactly one of the following parameters needs to be present: (kid, jwk, x5c)"
    )]
    MissingKeyParameters,
    #[error("Too many key parameters specified, exactly one of the following parameters needs to be present: (kid, jwk, x5c)"
    )]
    TooManyKeyParameters,
    #[error("Could not retrieve JWK from KID: {0}")]
    KIDDereferenceError(String),
    #[error(transparent)]
    DIDDereferenceError(#[from] ssi_dids_core::resolution::Error),
    #[error(transparent)]
    InvalidDIDURL(#[from] ssi_dids_core::InvalidDIDURL<String>),
    #[error(transparent)]
    ProofValidationError(#[from] ssi_claims::ProofValidationError),
}

impl ProofOfPossession {
    pub fn generate(params: &ProofOfPossessionParams, expiry: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        Self::generate_at(params, now, expiry)
    }

    fn generate_at(
        params: &ProofOfPossessionParams,
        issued_at: OffsetDateTime,
        lifetime: Duration,
    ) -> Self {
        let not_before = params
            .not_before
            .as_ref()
            .map(|nbf| nbf.gen_relative_to(&issued_at));

        let expires_at = if let Some(nbf) = not_before {
            issued_at.max(nbf) + lifetime
        } else {
            issued_at + lifetime
        };
        Self {
            body: ProofOfPossessionBody {
                issuer: params.issuer.clone(),
                audience: params.audience.clone(),
                not_before,
                issued_at: Some(issued_at),
                expires_at,
                nonce: params.nonce.clone(),
            },
            controller: params.controller.clone(),
        }
    }

    fn to_unsigned_jwt(&self) -> Result<(Header, String), ConversionError> {
        let jwk = &self.controller.jwk;
        let alg = if let Some(a) = jwk.get_algorithm() {
            a
        } else {
            return Err(ConversionError::MissingJWKAlg);
        };
        let payload = serde_json::to_string(&self.body)?;
        let (h_kid, h_jwk) = match (self.controller.vm.clone(), jwk.key_id.clone()) {
            (Some(vm), _) => (Some(vm.to_string()), None),
            (None, Some(kid)) => (Some(kid), None),
            (None, None) => (None, Some(jwk.to_public())),
        };
        let header = Header {
            algorithm: alg,
            key_id: h_kid,
            jwk: h_jwk,
            type_: Some(JWS_TYPE.to_string()),
            ..Default::default()
        };
        Ok((header, payload))
    }

    pub fn to_jwt_signing_input(&self) -> Result<Vec<u8>, ConversionError> {
        let (header_b64, payload_b64) = self.encode_header_and_payload()?;

        let signing_input = [header_b64.as_bytes(), b".", payload_b64.as_bytes()]
            .concat()
            .to_vec();
        Ok(signing_input)
    }

    pub fn to_jwt_with_signature(&self, signature: Vec<u8>) -> Result<String, ConversionError> {
        use base64::prelude::*;

        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let (header_b64, payload_b64) = self.encode_header_and_payload()?;
        let sig_b64 = encoder.encode(signature);
        let jws = [header_b64, payload_b64, sig_b64].join(".");

        Ok(jws)
    }

    fn encode_header_and_payload(&self) -> Result<(String, String), ConversionError> {
        use base64::prelude::*;

        let (header, payload) = self.to_unsigned_jwt()?;

        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let h_json = serde_json::to_string(&header)?;
        let header_b64 = encoder.encode(&h_json);
        let payload_b64 = encoder.encode(payload);

        Ok((header_b64, payload_b64))
    }

    pub fn to_jwt(&self) -> Result<String, ConversionError> {
        let jwk = &self.controller.jwk;
        let (header, payload) = self.to_unsigned_jwt()?;
        Ok(jws::encode_sign_custom_header(&payload, jwk, &header)?)
    }

    pub async fn from_proof(
        proof: &Proof,
        resolver: impl JWKResolver,
    ) -> Result<Self, ParsingError> {
        match proof {
            Proof::Jwt { jwt } => Self::from_jwt(jwt, resolver).await,
            Proof::DiVp { .. } => todo!(),
        }
    }

    pub async fn get_unverified_body(proof: &Proof) -> Result<ProofOfPossessionBody, ParsingError> {
        match proof {
            Proof::Jwt { jwt } => {
                let body = jwt::decode_unverified(jwt)?;
                Ok(body)
            }
            Proof::DiVp { .. } => todo!(),
        }
    }

    pub async fn from_jwt(jwt: &str, resolver: impl JWKResolver) -> Result<Self, ParsingError> {
        let header: Header = jws::decode_unverified(jwt)?.0;

        if header.type_ != Some(JWS_TYPE.to_string()) {
            return Err(ParsingError::InvalidJWSType {
                actual: format!("{:?}", header.type_),
                expected: JWS_TYPE.to_string(),
            });
        }
        if header.algorithm == Algorithm::None {
            return Err(ParsingError::MissingJWSAlg);
        }
        let (controller, jwk) = match (header.key_id, header.jwk, header.x509_certificate_chain) {
            (Some(kid), None, None) => {
                let vm = kid.parse()?;
                //get_jwk_from_kid(&kid, resolver)
                resolver
                    .fetch_public_jwk(Some(&kid))
                    .await
                    .map(|r| (Some(vm), r.into_owned()))?
            }
            (None, Some(jwk), None) => (None, jwk),
            (None, None, Some(_x5c)) => {
                unimplemented!();
            }
            (None, None, None) => return Err(ParsingError::MissingKeyParameters),
            _ => return Err(ParsingError::TooManyKeyParameters),
        };
        let body = jwt::decode_verify(jwt, &jwk)?;
        Ok(Self {
            body,
            controller: ProofOfPossessionController {
                vm: controller,
                jwk,
            },
        })
    }

    pub async fn verify(
        &self,
        params: &ProofOfPossessionVerificationParams,
    ) -> Result<(), VerificationError> {
        let now = OffsetDateTime::now_utc();
        self.verify_at(params, now).await
    }

    async fn verify_at(
        &self,
        params: &ProofOfPossessionVerificationParams,
        now: OffsetDateTime,
    ) -> Result<(), VerificationError> {
        let nbf_tolerance = params.nbf_tolerance.unwrap_or_default();
        let exp_tolerance = params.exp_tolerance.unwrap_or_default();

        if let Some(not_before) = self.body.not_before {
            if (now + nbf_tolerance) < not_before {
                return Err(VerificationError::NotYetValid);
            }
        }

        if (now - exp_tolerance) > self.body.expires_at {
            return Err(VerificationError::Expired);
        }

        if self.body.issuer != params.issuer {
            return Err(VerificationError::InvalidIssuer {
                expected: params.issuer.clone().unwrap_or_default(),
                actual: self.body.issuer.clone().unwrap_or_default(),
            });
        }

        if self.body.audience != params.audience {
            return Err(VerificationError::InvalidAudience {
                expected: params.audience.clone(),
                actual: self.body.audience.clone(),
            });
        }

        if self.body.nonce != params.nonce {
            return Err(VerificationError::InvalidNonce);
        }

        if let Some(jwk) = &params.controller_jwk {
            if jwk != &self.controller.jwk {
                return Err(VerificationError::InvalidJWK);
            }
        }
        if let Some(did) = &params.controller_did {
            if self.controller.vm.is_none() {
                return Err(VerificationError::InvalidDID {
                    expected: did.to_string(),
                    actual: format!("{:?}", self.controller.vm),
                });
            }
        }

        Ok(())
    }
}
#[cfg(test)]
mod test {
    use did_jwk::DIDJWK;
    use did_method_key::DIDKey;
    use rstest::*;
    use serde_json::json;
    use ssi_dids_core::{DIDResolver, VerificationMethodDIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods::AnyMethod;

    use super::*;

    #[fixture]
    fn issuer() -> String {
        "TEST_ISSUER".to_owned()
    }

    #[fixture]
    fn audience() -> String {
        "http://localhost:300".to_owned()
    }

    #[fixture]
    fn jwk() -> JWK {
        serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"h3GzIK3pU8oTspVBKstiPSHR3VH_USS2FA0NrAOZ51s","d":"pfYMFvJ-LlMO4-EBBsrjpfAVz5UEYNVgbTphLPZypbE"})).unwrap()
    }

    #[fixture]
    fn nonce() -> Option<Nonce> {
        None
    }

    #[fixture]
    fn did_url(jwk: JWK) -> DIDURLBuf {
        DIDJWK::generate_url(&jwk)
    }

    #[fixture]
    fn pop_params(
        issuer: String,
        audience: String,
        nonce: Option<Nonce>,
        jwk: JWK,
        did_url: DIDURLBuf,
    ) -> ProofOfPossessionParams {
        ProofOfPossessionParams {
            issuer: Some(issuer),
            audience,
            nonce,
            controller: ProofOfPossessionController {
                jwk,
                vm: Some(did_url.clone()),
            },
            not_before: None,
        }
    }

    #[fixture]
    fn pop_verification_params(
        #[default(None)] nbf_tolerance: Option<Duration>,
        #[default(None)] exp_tolerance: Option<Duration>,
        issuer: String,
        audience: String,
        nonce: Option<Nonce>,
        did_url: DIDURLBuf,
    ) -> ProofOfPossessionVerificationParams {
        ProofOfPossessionVerificationParams {
            issuer: Some(issuer),
            nonce,
            audience,
            controller_did: Some(did_url),
            controller_jwk: None,
            nbf_tolerance,
            exp_tolerance,
        }
    }

    #[tokio::test]
    #[rstest]
    async fn basic(
        pop_params: ProofOfPossessionParams,
        pop_verification_params: ProofOfPossessionVerificationParams,
    ) {
        let expires_in = Duration::minutes(5);
        let pop = ProofOfPossession::generate(&pop_params, expires_in);

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        pop.verify(&pop_verification_params).await.unwrap();
    }

    #[tokio::test]
    async fn basic_didkey_p256() {
        let expires_in = Duration::minutes(5);
        let jwk = JWK::generate_p256();
        let did_url = DIDKey::generate_url(&jwk).unwrap();
        let pop_jwt = ProofOfPossession::generate(
            &ProofOfPossessionParams {
                issuer: Some("test".to_string()),
                audience: "http://localhost:300".to_string(),
                nonce: None,
                controller: ProofOfPossessionController {
                    jwk,
                    vm: Some(did_url.clone()),
                },
                not_before: Some(ProofOfPossessionNotBefore::AsIssuedAt),
            },
            expires_in,
        )
        .to_jwt()
        .unwrap();
        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDKey.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();
        pop.verify(&ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: Some("test".to_string()),
            controller_did: Some(did_url),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[rstest]
    async fn nbf_tolerance(
        pop_params: ProofOfPossessionParams,
        mut pop_verification_params: ProofOfPossessionVerificationParams,
    ) {
        let expires_in = Duration::minutes(5);
        let mut pop = ProofOfPossession::generate(&pop_params, expires_in);

        // Not to be used before now + 5 minutes.
        pop.body.not_before = Some(OffsetDateTime::now_utc() + Duration::minutes(5));

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        pop.verify(&pop_verification_params)
            .await
            .expect_err("should have failed due to nbf");

        pop_verification_params.nbf_tolerance = Some(Duration::minutes(5));

        pop.verify(&pop_verification_params)
            .await
            .expect("should have passed with nbf tolerance");
    }

    #[tokio::test]
    #[rstest]
    async fn exp_tolerance(
        pop_params: ProofOfPossessionParams,
        mut pop_verification_params: ProofOfPossessionVerificationParams,
    ) {
        // Expires immediately.
        let expires_in = Duration::ZERO;
        let pop = ProofOfPossession::generate(&pop_params, expires_in);

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        pop.verify(&pop_verification_params)
            .await
            .expect_err("should have failed due to exp");

        pop_verification_params.exp_tolerance = Some(Duration::minutes(5));

        pop.verify(&pop_verification_params)
            .await
            .expect("should have passed with exp tolerance");
    }

    #[tokio::test]
    #[rstest]
    #[case(OffsetDateTime::now_utc(), None, None)]
    #[case(
        OffsetDateTime::from_unix_timestamp(100).unwrap(),
        Some(ProofOfPossessionNotBefore::AsIssuedAt),
        OffsetDateTime::from_unix_timestamp(100).ok())]
    #[case(
        OffsetDateTime::from_unix_timestamp(100).unwrap(),
        Some(ProofOfPossessionNotBefore::Fixed(OffsetDateTime::from_unix_timestamp(200).unwrap())),
        OffsetDateTime::from_unix_timestamp(200).ok())]
    #[case(
        OffsetDateTime::from_unix_timestamp(100).unwrap(),
        Some(ProofOfPossessionNotBefore::Delay(Duration::seconds(10))),
        OffsetDateTime::from_unix_timestamp(110).ok())]
    #[case(
        OffsetDateTime::from_unix_timestamp(100).unwrap(),
        Some(ProofOfPossessionNotBefore::Leeway(Duration::seconds(10))),
        OffsetDateTime::from_unix_timestamp(90).ok())]
    async fn nbf_generation(
        mut pop_params: ProofOfPossessionParams,
        pop_verification_params: ProofOfPossessionVerificationParams,
        #[case] iat: OffsetDateTime,
        #[case] not_before: Option<ProofOfPossessionNotBefore>,
        #[case] not_before_expected: Option<OffsetDateTime>,
    ) {
        pop_params.not_before = not_before;
        let pop = ProofOfPossession::generate_at(&pop_params, iat, Duration::minutes(5));

        assert_eq!(not_before_expected, pop.body.not_before);

        assert_eq!(
            Err(VerificationError::Expired),
            pop.verify_at(
                &pop_verification_params,
                pop.body.expires_at + Duration::seconds(1)
            )
            .await
        );

        if not_before_expected.is_none() {
            return;
        }

        assert_eq!(
            Ok(()),
            pop.verify_at(
                &pop_verification_params,
                pop.body.not_before.unwrap() + Duration::seconds(1)
            )
            .await
        );

        assert_eq!(
            Err(VerificationError::NotYetValid),
            pop.verify_at(
                &pop_verification_params,
                pop.body.not_before.unwrap() - Duration::seconds(1)
            )
            .await
        );
    }

    #[tokio::test]
    #[rstest]
    #[case(
        OffsetDateTime::now_utc(),
        ProofOfPossessionNotBefore::AsIssuedAt,
        Duration::minutes(5),
        Duration::minutes(5)
    )]
    #[case(
        OffsetDateTime::now_utc(),
        ProofOfPossessionNotBefore::Delay(Duration::minutes(5)),
        Duration::minutes(5),
        Duration::minutes(5)
    )]
    #[case(
        OffsetDateTime::now_utc(),
        ProofOfPossessionNotBefore::Leeway(Duration::minutes(5)),
        Duration::minutes(5),
        Duration::minutes(10)
    )]
    async fn lifetime(
        mut pop_params: ProofOfPossessionParams,
        #[case] iat: OffsetDateTime,
        #[case] nbf: ProofOfPossessionNotBefore,
        #[case] expiry: Duration,
        #[case] total_lifetime: Duration,
    ) {
        pop_params.not_before = Some(nbf);

        let pop = ProofOfPossession::generate_at(&pop_params, iat, expiry);
        assert_eq!(iat, pop.body.issued_at.unwrap());

        let exp = pop.body.expires_at;

        let actual_lifetime = exp - pop.body.not_before.unwrap_or(iat);
        assert_eq!(total_lifetime, actual_lifetime);
    }

    #[tokio::test]
    async fn nbf_deserialize_absent_in_json() {
        let payload = "eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjM1MDAxIiwiaWF0IjoxNzU0NjM3OTQ0LCJleHAiOjE3NTQ2MzgyNDQsIm5vbmNlIjoiVVdUWkRZQXdTbUdYek91ejFFb0pWeW9veUo3UXd1T3JhYVB3YVdLcjBBUSJ9";
        #[allow(deprecated)]
        let payload = base64::decode(payload).unwrap();
        let body: ProofOfPossessionBody = serde_json::from_slice(&payload).unwrap();

        assert_eq!(None, body.not_before);
    }
}
