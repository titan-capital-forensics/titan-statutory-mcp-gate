# Changelog

All notable changes to **`titan-statutory-mcp-gate`** (`com.titancapitalforensics/statutory-gate`) are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project strictly adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-27

### Added
- Comprehensive automated `pytest` test suite (`tests/test_gate_engine.py`) covering all 5 deterministic statutory diagnostic tools, fail-closed parameter validation, zero-freebie / prompt-injection refusal guards, RFC 8032 `Ed25519` & `SHA-256` cryptographic verification, JSON-RPC 2.0 protocol negotiation, and CLI stdio transport.
- Continuous Integration & static security analysis workflow (`.github/workflows/ci.yml`) executing `pytest -W error`, `ruff`, and `bandit` across Python `3.10`–`3.13`.
- Official OpenSSF governance and disclosure documentation: `SECURITY.md` (with OpenPGP Ed25519 encrypted private reporting), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `CHANGELOG.md`.
- OpenSSF Best Practices Badge tracking (`https://www.bestpractices.dev/en/projects/17188`).

### Changed
- Aligned `SERVER_VERSION` in `src/titan_statutory_mcp_gate/gate_engine.py` with `pyproject.toml` and `server.json` (`1.0.1`).
- Removed unused `serialization` import in `gate_engine.py` for zero-warning static analysis cleanliness.

### Security
- Hardened `probe_remote()` in `src/titan_statutory_mcp_gate/cli.py` to strictly reject non-`https://` endpoint URLs before initiating network I/O (mitigating cleartext transport and `file://` scheme risks).
- Zero known vulnerabilities addressed in this release; security disclosures are published in this section for every release.

## [1.0.0] - 2026-11-18

### Added
- Initial public Apache-2.0 release of `com.titancapitalforensics/statutory-gate` MCP server and `stdio` CLI.
- Five stateless deterministic diagnostic tools covering US CBP Drawback (`19 U.S.C. § 1313`), EU CBAM & EUDR, IRS Section 179D & DoD CMMC 2.0, UAE QFZP & EU GDPR, and `Ed25519` workpaper hash verification.
- Official `server.json` MCP Registry metadata and `glama.json` catalog metadata.
