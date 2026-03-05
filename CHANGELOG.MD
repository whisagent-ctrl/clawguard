# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by Keep a Changelog and Semantic Versioning principles.

## [Unreleased]

### Added
- Minimal CI pipeline via GitHub Actions (`.github/workflows/ci.yml`) to run build + tests on push to `main` and on pull requests.
- Baseline automated tests for `security.ts` helpers (`tests/security.test.js`).

### Changed
- Approval scope is now more granular: approvals are separated by **service + HTTP method** (not only by service).
- README roadmap updated to reflect the new per-method approval behavior.
- Roadmap expanded with planned policy scope selector: `method` only, or `service + method + path prefix`, or `service + method + exact path`.

## [0.2.0]

### Added
- Telegram approval flow with time-limited approvals.
- Audit trail and admin dashboard.
- Forwarder mode for hardcoded SDK URLs.
- Security checks (allowlist, SSRF blocking, runtime URL validation).
