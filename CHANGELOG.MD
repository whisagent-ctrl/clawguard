# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed
- Roadmap updated with planned policy scope selector for approvals: `method` only, or `service + method + path prefix`, or `service + method + exact path`.

## [2026-03-05]

### Changed
- Approval scope is now more granular: approvals are separated by **service + HTTP method** (not only by service).
- README roadmap updated to reflect the new per-method approval behavior.
- Restored Docker bridge IP note in README for admin dashboard `allowedIPs` when running in Docker.

### Added
- Minimal CI pipeline via GitHub Actions (`.github/workflows/ci.yml`) to run build + tests on push to `main` and on pull requests.
- Baseline automated tests for `security.ts` helpers (`tests/security.test.js`).
