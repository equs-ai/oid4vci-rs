# Changelog

All notable changes to this fork are documented here.

This is a fork of [spruceid/oid4vci-rs](https://github.com/spruceid/oid4vci-rs),
diverged at `a802dfe`.

### Added

- `vc_sd_jwt` profile, a shared `claims` module, and a full `jwt_vc_json_ld` profile.
- Deferred credential and notification request builders.

### Changed

- Updated to OpenID4VCI 1.0.
- Published as `equs-oid4vci`; the library target stays `oid4vci`, so `use oid4vci::…` is unchanged.
