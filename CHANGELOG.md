# Changelog

All notable changes to this fork are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is a fork of [spruceid/oid4vci-rs](https://github.com/spruceid/oid4vci-rs),
diverged at `12e8999` ("Pushed Authorization Request support"). Upstream history
before that point is not repeated here.

## [Unreleased]

### Added

- SD-JWT VC issuance interface and profile.
- Holder-side OID4VCI: SD-JWT profile, `scope` and `response_type` on pushed
  authorization requests.
- Issuer-side OID4VCI endpoints.
- Credential offer core profile.
- Nonce endpoint (draft 15).
- `batch_credential_issuance` in credential issuer metadata.
- `nbf` configuration parameters.
- Additional and custom fields on `CredentialOfferParameters`.
- Deferred credential request builder, plus `interval` on the deferred
  credential response.
- Notification request builder and client API for sending notifications.
- Method to set the token URL on `PreAuthorizedCodeTokenRequest`.
- Extra validation across the main OID4VCI flow.
- Apache-2.0 licence text (`Cargo.toml` already declared `Apache-2.0 OR MIT`).

### Changed

- Credential request and response entities updated to draft 15.
- Credential issuance flow updated to draft 15.
- Issuer metadata updated to draft 15; credential metadata to draft 17.
- Metadata discovery API reworked.
- Authorization server / issuer metadata URLs built per RFC 8414.
- Issuer and credential metadata structures restructured.
- Credential response handling now matches on the error reason.
- `vc+sd-jwt` renamed to `dc+sd-jwt`.
- Proof-of-possession type `ldp_vp` renamed to `di_vp`.
- `ErrorType` variants updated.
- HTTP client reworked for end-to-end tests.
- `ssi` bumped to 0.16.0; `serde` pinned to 1.0.221.

### Removed

- `format` and `credential_definition` from the authorization request.
- `proof` from the credential request.
- `order` from metadata credential configurations.
- Redundant protocol error variants and bodies from request errors.

### Fixed

- SD-JWT credential metadata.
- `vct` handling in the SD-JWT profile.
- Token authorization response.
