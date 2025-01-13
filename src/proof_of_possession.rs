// use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::{
    jws::{self, Header},
    jwt,
};
use ssi_dids_core::DIDURLBuf;
use ssi_jwk::{Algorithm, JWKResolver, JWK};
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
    #[serde(rename = "cwt")]
    Cwt,
    #[serde(rename = "ldp_vp")]
    LdpVp,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "proof_type")]
pub enum Proof {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    #[serde(rename = "cwt")]
    Cwt { cwt: String },
    #[serde(rename = "ldp_vp")]
    LdpVp { ldp_vp: Value },
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
    pub not_before: Option<OffsetDateTime>,
    #[serde(rename = "iat")]
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub issued_at: Option<OffsetDateTime>,
    #[serde(rename = "exp", with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    #[serde(rename = "nonce")]
    pub nonce: Nonce,
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
}

pub struct ProofOfPossessionVerificationParams {
    pub audience: String,
    pub issuer: Option<String>,
    pub nonce: Nonce,
    pub controller_did: Option<DIDURLBuf>,
    pub controller_jwk: Option<JWK>,
    /// Slack in nbf validation to deal with clock synchronisation issues.
    pub nbf_tolerance: Option<Duration>,
    /// Slack in exp validation to deal with clock synchronisation issues.
    pub exp_tolerance: Option<Duration>,
}

#[derive(thiserror::Error, Debug)]
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
    #[error("Missing key parameter, exactly one of the following parameters needs to be present: (kid, jwk, x5c)")]
    MissingKeyParameters,
    #[error("Too many key parameters specified, exactly one of the following parameters needs to be present: (kid, jwk, x5c)")]
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

// #[async_trait]
// pub trait Signer: Sync + Send {
//     async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, jws::Error>;
// }

impl ProofOfPossession {
    pub fn generate(params: &ProofOfPossessionParams, expiry: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp = now + expiry;
        Self {
            body: ProofOfPossessionBody {
                issuer: params.issuer.clone(),
                audience: params.audience.clone(),
                not_before: Some(now),
                issued_at: Some(now),
                expires_at: exp,
                nonce: params.nonce.clone().unwrap_or_else(Nonce::new_random),
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
            Proof::Cwt { .. } => todo!(),
            Proof::LdpVp { .. } => todo!(),
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
    use serde_json::json;
    use ssi_dids_core::{DIDResolver, VerificationMethodDIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods::AnyMethod;

    use super::*;

    fn generate_pop(expires_in: Duration) -> (ProofOfPossession, DIDURLBuf) {
        let jwk: JWK = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"h3GzIK3pU8oTspVBKstiPSHR3VH_USS2FA0NrAOZ51s","d":"pfYMFvJ-LlMO4-EBBsrjpfAVz5UEYNVgbTphLPZypbE"})).unwrap();
        let did_url = DIDJWK::generate_url(&jwk);

        (
            ProofOfPossession::generate(
                &ProofOfPossessionParams {
                    issuer: Some("test".to_string()),
                    audience: "http://localhost:300".to_string(),
                    nonce: None,
                    controller: ProofOfPossessionController {
                        jwk,
                        vm: Some(did_url.clone()),
                    },
                },
                expires_in,
            ),
            did_url,
        )
    }

    #[tokio::test]
    async fn basic() {
        let expires_in = Duration::minutes(5);

        let (pop, did) = generate_pop(expires_in);

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        pop.verify(&ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: Some("test".to_string()),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn basic_didkey_p256() {
        let expires_in = Duration::minutes(5);
        let jwk = JWK::generate_p256();
        let did_url = DIDKey::generate_url(&jwk).unwrap();
        let pop_jwt = ProofOfPossession::generate(
            &ProofOfPossessionParams {
                issuer: Some("test".to_string()),
                // audience: Url::parse("http://localhost:300").unwrap(),
                audience: "http://localhost:300".to_string(),
                nonce: None,
                controller: ProofOfPossessionController {
                    jwk,
                    vm: Some(did_url.clone()),
                },
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
    async fn nbf_tolerance() {
        let expires_in = Duration::minutes(5);

        let (mut pop, did) = generate_pop(expires_in);

        // Not to be used before now + 5 minutes.
        let nbf = Some(OffsetDateTime::now_utc() + Duration::minutes(5));

        pop.body.not_before = nbf;

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        let mut verification_params = ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: Some("test".to_string()),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        };

        pop.verify(&verification_params)
            .await
            .expect_err("should have failed due to nbf");

        verification_params.nbf_tolerance = Some(Duration::minutes(5));

        pop.verify(&verification_params)
            .await
            .expect("should have passed with nbf tolerance");
    }

    #[tokio::test]
    async fn exp_tolerance() {
        // Expires immediately.
        let expires_in = Duration::minutes(0);

        let (pop, did) = generate_pop(expires_in);

        let pop_jwt = pop.to_jwt().unwrap();

        let resolver: VerificationMethodDIDResolver<_, AnyMethod> = DIDJWK.into_vm_resolver();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, resolver)
            .await
            .unwrap();

        let mut verification_params = ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: Some("test".to_string()),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        };

        pop.verify(&verification_params)
            .await
            .expect_err("should have failed due to exp");

        verification_params.exp_tolerance = Some(Duration::minutes(5));

        pop.verify(&verification_params)
            .await
            .expect("should have passed with exp tolerance");
    }

    // struct TestSigner {
    //     jwk: JWK,
    // }

    // #[async_trait]
    // impl Signer for TestSigner {
    //     async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    //         jws::sign_bytes(self.jwk.get_algorithm().unwrap(), data, &self.jwk)
    //     }
    // }
}
