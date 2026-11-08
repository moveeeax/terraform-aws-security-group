# Changelog

All notable changes to this module are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-11-08

### Added

- Ingress and egress rules accept `security_groups`, `prefix_list_ids` and
  `self`, so a rule can reference another security group, a managed prefix
  list or the group itself instead of a CIDR. IDs are format-checked at plan
  time. Existing CIDR-only rules plan unchanged.
- An egress rule that omits `cidr_blocks` but names a security group, prefix
  list or `self` gets `cidr_blocks = []`, not the `["0.0.0.0/0"]` fallback.
  Rules that name none of those keep the `["0.0.0.0/0"]` fallback.

## [1.1.0] - 2026-11-05

### Fixed

- `ipv6_cidr_blocks` on ingress and egress rules, so IPv6 CIDRs no longer go
  to the API as malformed IPv4 `cidr_blocks`.

### Changed

- CI: add tflint, move actions to their node24 majors, pin tool versions.

## [1.0.0] - 2026-07-26

Initial release (`v0.1.0` points at the same commit).

[Unreleased]: https://github.com/moveeeax/terraform-aws-security-group/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/moveeeax/terraform-aws-security-group/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/moveeeax/terraform-aws-security-group/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/moveeeax/terraform-aws-security-group/releases/tag/v1.0.0
