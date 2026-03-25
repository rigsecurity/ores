# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core scoring engine with 8 signal types (CVSS, EPSS, threat intel, asset, blast radius, NIST, compliance, patch)
- CLI with `evaluate`, `signals`, and `version` commands
- Daemon with ConnectRPC (HTTP + gRPC) including health and readiness endpoints
- WASM module (wasip1) for browser and edge runtimes via stdin/stdout JSON FFI
- MkDocs Material documentation site with full API reference and user guide
- CI/CD with GitHub Actions (test, lint, build, release workflows)
- GoReleaser for multi-platform releases (Linux, macOS, Windows; amd64 + arm64)
- Basic library usage example (`examples/basic/`)
