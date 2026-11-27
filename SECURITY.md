# Security Policy — TITAN Statutory Gate (`com.titancapitalforensics/statutory-gate`)

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Supported |
| `< 1.0.0` | Unsupported |

## Reporting a Vulnerability (Private Disclosure)

**TITAN Capital Forensics LLC** welcomes responsible disclosure from security researchers and users. Please **do not** report security vulnerabilities in public GitHub issues.

Report vulnerabilities privately through either channel:

1. **GitHub Private Vulnerability Reporting:** Use the **Security -> Advisories -> Report a vulnerability** button on this repository (`https://github.com/titan-capital-forensics/titan-statutory-mcp-gate/security/advisories/new`).
2. **Encrypted Email:** Email **`audit@titancapitalforensics.com`** encrypted with our published OpenPGP Ed25519 key:
   - **OpenPGP Fingerprint:** `F38185B9E58B9AA560D9A0AC3DEEC6D7518051E1`
   - **Verified Cryptographic Identity:** `https://keyoxide.org/F38185B9E58B9AA560D9A0AC3DEEC6D7518051E1`
   - **Canonical `security.txt`:** `https://titancapitalforensics.com/.well-known/security.txt`

## Response & Remediation Commitments

- **Initial Response:** We acknowledge and provide an initial substantive response to all private vulnerability reports within **14 calendar days** (target: 48 business hours).
- **Remediation Targets:** Critical and publicly known high-severity vulnerabilities are triaged immediately and fixed as rapidly as safely possible, targeting remediation within **60 days** for all confirmed vulnerabilities.
- **Transparency:** Confirmed security fixes are documented clearly in `CHANGELOG.md` and GitHub Releases, with CVE/CWE references published where applicable.
- **Good-Faith Safe Harbor:** TITAN Capital Forensics LLC will not pursue legal action against researchers who conduct good-faith security testing on this open-source client and follow coordinated disclosure practices.

## Architectural Security Properties

- **Zero Secrets / Zero Credential Storage:** This package stores zero private keys, zero passwords, and zero session secrets. Only the public Ed25519 verification key is embedded.
- **Strict Input Validation & Fail-Closed Design:** All numeric inputs reject `NaN`/`Infinity`/out-of-range values; string inputs enforce hard length bounds; remote probes enforce `https://` TLS transport exclusively.
- **Standard Published Cryptography:** Uses RFC 8032 `Ed25519` and FIPS 180-4 `SHA-256` exclusively via the audited Python `cryptography` (OpenSSL/Rust) library and Python `hashlib`.
