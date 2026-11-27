# Contributing to TITAN Statutory Gate

Thank you for your interest in contributing to **`titan-statutory-mcp-gate`** (`com.titancapitalforensics/statutory-gate`), an Apache-2.0 open-source stateless diagnostic MCP server and client maintained by **TITAN Capital Forensics LLC**.

## How to Contribute

1. **Bug Reports & Feature Requests:** Open an issue in the public GitHub issue tracker (`https://github.com/titan-capital-forensics/titan-statutory-mcp-gate/issues`) with clear reproduction steps, expected vs. actual behavior, and environment details.
2. **Pull Requests:** Fork the repository, create a focused feature/fix branch from `main`, include automated unit tests, and submit a Pull Request describing the change and statutory reference (where applicable).
3. **Security Issues:** Never open a public issue for security vulnerabilities. Follow [SECURITY.md](SECURITY.md) for private encrypted reporting.

## Development & Automated Testing Policy

Every change that adds major functionality or fixes a bug **must** include corresponding automated regression tests in `tests/`.

### Local Setup & Verification

```bash
python3 -m pip install -e ".[dev]"
pytest -v -W error
ruff check src tests
bandit -r src
```

All pull requests are automatically validated by GitHub Actions CI (`.github/workflows/ci.yml`) across Python `3.10`, `3.11`, `3.12`, and `3.13`, enforcing:

- Zero compiler/runtime warnings (`pytest -W error`)
- Strict static linting (`ruff check`)
- Automated static security analysis (`bandit -r src`)
- Zero leaked secrets and zero third-party telemetry

## Licensing & Conduct

- All contributions are licensed under the **Apache License 2.0** (`LICENSE`).
- All contributors agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
