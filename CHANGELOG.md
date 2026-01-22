# Changelog

All notable changes to this project will be documented in this file.

The format is based on "Keep a Changelog" and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- `trivium_xor` helper: removed the `bit_order` parameter; helper now defaults to MSB for key/IV bit interpretation.

### Added
- Public API for advanced usage: `Trivium`, `BitOrder`, `PackOrder`, `Trivium::new` and `Trivium::xor_bytes`.
- Example/docs showing both the simple helper and direct usage via `Trivium::new`.

### Removed
- `parse_bit_order` helper function (no longer needed).

<!--
When releasing, move the Unreleased heading to a versioned release like:

## [1.0.0] - 2026-01-22

and add any relevant notes as necessary.
-->
