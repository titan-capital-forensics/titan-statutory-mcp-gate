# TITAN Statutory Gate (`com.titancapitalforensics/statutory-gate`)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/17188/badge)](https://www.bestpractices.dev/projects/17188)
[![CI & Security Analysis](https://github.com/titan-capital-forensics/titan-statutory-mcp-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/titan-capital-forensics/titan-statutory-mcp-gate/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

<!-- mcp-name: com.titancapitalforensics/statutory-gate -->

Stateless diagnostic statutory applicability, schema readiness, and `Ed25519` workpaper signature verification Model Context Protocol (MCP) server operated by **TITAN Capital Forensics LLC** (Registered Jurisdiction: Albuquerque, New Mexico, USA).

- **Remote Streamable HTTP MCP (`protocolVersion: "2025-06-18"`):** `https://mcp.titancapitalforensics.com/mcp`
- **Discovery Manifest:** `https://mcp.titancapitalforensics.com/.well-known/mcp.json`
- **Service Health:** `https://mcp.titancapitalforensics.com/health`
- **Published Ed25519 Authority Key:** `https://titancapitalforensics.com/.well-known/titan-ed25519-pub.pem`
- **Corporate Headquarters Portal:** `https://titancapitalforensics.com/`

---

## Architectural Overview & Zero-Data-Retention Guarantee

`TITAN Statutory Gate` enables AI coding assistants, autonomous enterprise procurement agents, ERP connectors, and audit workbenches to verify statutory scope, threshold triggers, regulatory schema requirements, and cryptographic `Ed25519` workpaper seals in real time with **zero credentials, zero PII transmission, and zero third-party trackers**.

### Five Deterministic Diagnostic Tools

1. **`check_cbp_drawback_eligibility`** — Evaluates `19 U.S.C. § 1313(j)(2)` / `19 CFR Part 190` substitution duty drawback scope, 8-digit HTSUS vs. Schedule B alignment, and the 5-year (`1,825`-day) TFTEA lookback boundary.
2. **`check_eu_cbam_eudr_mandate`** — Evaluates EU Definitive CBAM (`Regulation (EU) 2023/956` & `Regulation (EU) 2025/2083` 50-tonne cumulative mass rule) and EU Deforestation Regulation (`Regulation (EU) 2023/1115` Art. 9 GeoJSON polygon closure vs. `<= 4` ha rule).
3. **`check_irs_179d_cmmc_readiness`** — Evaluates `26 U.S.C. § 179D` (`IRS Form 7205` ASHRAE commercial building deduction & prevailing-wage 5x multiplier) and DoD `CMMC 2.0` / `NIST SP 800-171` (`32 CFR Part 170` SPRS floor & 180-day POA&M boundary).
4. **`check_uae_qfzp_gdpr_trigger`** — Evaluates UAE Corporate Tax Qualifying Free Zone Person `5%` / `AED 5,000,000` de-minimis cliff (`Federal Decree-Law No. 47 of 2022 Art. 18`) and EU GDPR `Art. 3 / 30 / 35` RoPA & DPIA mandates.
5. **`verify_titan_ed25519_workpaper_hash`** — Cryptographically verifies `SHA-256` digests and `Ed25519` authority signatures on official TITAN statutory audit dossiers against our published public key.

> **Commercial Boundary**: Public MCP tools return strictly deterministic statutory applicability verdicts, official citations, schema readiness checklists, and direct institutional licensing endpoints. Full mathematical schedules, Microsoft Z3 formal proofs, regulator-ready XML/GeoJSON submissions, and `Ed25519`-sealed audit workpapers execute exclusively inside licensed TITAN portals.

---

## Quick Connect (Zero Installation — Remote Streamable HTTP)

Add to `.mcp.json`, `.cursor/mcp.json`, Windsurf, VS Code Copilot, or Claude Desktop configuration:

```json
{
  "mcpServers": {
    "titan-statutory-gate": {
      "type": "http",
      "url": "https://mcp.titancapitalforensics.com/mcp"
    }
  }
}
```

### Local `stdio` Bridge / CLI Probe (Optional)

```bash
pip install .
titan-statutory-mcp-gate --probe-remote
```

---

## Sovereign 14-Portal Compliance & Forensic Suite

All 14 commercial portals are operated by **TITAN Capital Forensics LLC** (Albuquerque, New Mexico, USA) under uniform institutional licensing (**`$495` Single-Entity Statutory Audit License** | **`$295/mo` 100% White-Label Partner Desk** | **`$145/stamp` Additional Wholesale Client Stamp**):

| # | Sovereign Portal | Domain | Statutory & Forensic Framework | Institutional Checkout |
| :--- | :--- | :--- | :--- | :--- |
| **01** | **179D Shield** | `179dshield.com` | IRS Section 179D (`Form 7205`) ASHRAE Commercial Building Deduction | [Open Licensing Portal](https://179dshield.com/#titan-enterprise-checkout-modal) |
| **02** | **QFZP Shield** | `qfzpshield.com` | UAE `0%` Qualifying Free Zone Person (`Decree-Law 47/2022`) Substance & De-Minimis | [Open Licensing Portal](https://qfzpshield.com/#titan-enterprise-checkout-modal) |
| **03** | **CBAM Sovereign** | `cbamsovereign.com` | EU Definitive CBAM (`Reg. 2023/956` & `2025/2083`) Carbon Declarations | [Open Licensing Portal](https://cbamsovereign.com/#titan-enterprise-checkout-modal) |
| **04** | **CISO Pass** | `cisopass.com` | DoD CMMC 2.0 (`32 CFR 170`), NIST SP 800-171 SPRS & ISO 27001 Dossiers | [Open Licensing Portal](https://cisopass.com/#titan-enterprise-checkout-modal) |
| **05** | **Drawback Sovereign** | `drawbacksovereign.com` | US CBP Duty Drawback (`19 U.S.C. § 1313` / `19 CFR 190`) Refund Schedules | [Open Licensing Portal](https://drawbacksovereign.com/#titan-enterprise-checkout-modal) |
| **06** | **EUDR Polygon** | `eudrpolygon.com` | EU Deforestation Regulation (`Reg. 2023/1115`) GeoJSON Polygon Verification | [Open Licensing Portal](https://eudrpolygon.com/#titan-enterprise-checkout-modal) |
| **07** | **GDPR Kit** | `getgdprkit.com` | EU GDPR `Art. 30` RoPA & `Art. 35` Cross-Border DPIA Audit Packs | [Open Licensing Portal](https://getgdprkit.com/#titan-enterprise-checkout-modal) |
| **08** | **Workflow Kit** | `getworkflowkit.com` | Deterministic Internal Audit, SOX & Financial Control Checklists | [Open Licensing Portal](https://getworkflowkit.com/#titan-enterprise-checkout-modal) |
| **09** | **ICV Scorecard** | `icvscorecard.com` | UAE National ICV & KSA IKTVA Pre-Audit Simulation Workpapers | [Open Licensing Portal](https://icvscorecard.com/#titan-enterprise-checkout-modal) |
| **10** | **RFP Sniper** | `rfpsniper.com` | Enterprise RFP Security & Procurement Compliance Matrices | [Open Licensing Portal](https://rfpsniper.com/#titan-enterprise-checkout-modal) |
| **11** | **TITAN Capital Forensics** | `titancapitalforensics.com` | Multi-Jurisdiction Group Statutory Attestation & Cryptographic Seal Hub | [Open Licensing Portal](https://titancapitalforensics.com/#titan-enterprise-checkout-modal) |
| **12** | **TITAN DRM** | `titandrm.com` | C2PA Cryptographic Media Provenance & `.tdrm` Offline Capsule Verification | [Open Licensing Portal](https://titandrm.com/#titan-enterprise-checkout-modal) |
| **13** | **TITAN ScribeGuard** | `titan-scribeguard.com` | HIPAA Clinical Documentation & Healthcare Billing Compliance Audits | [Open Licensing Portal](https://titan-scribeguard.com/#titan-enterprise-checkout-modal) |
| **14** | **TITAN Trust Center** | `titantrustcenter.com` | Vendor Security Posture, Subprocessor & SOC 2 Evidence Dossiers | [Open Licensing Portal](https://titantrustcenter.com/#titan-enterprise-checkout-modal) |

---

## Security, Testing, Governance & Licensing

- **Zero Secrets / Zero Telemetry**: Stateless JSON-RPC 2.0 transport with zero analytics scripts, zero credential storage, and strict `https://` TLS-only remote probing.
- **Vulnerability Disclosure**: See [SECURITY.md](SECURITY.md) (encrypted reporting via `audit@titancapitalforensics.com` + OpenPGP `F38185B9E58B9AA560D9A0AC3DEEC6D7518051E1` or GitHub Private Advisories; 14-day response commitment).
- **Automated Testing & Static Analysis**: Run `pip install -e ".[dev]" && pytest -v -W error && ruff check src tests && bandit -r src` (see [CONTRIBUTING.md](CONTRIBUTING.md) and `.github/workflows/ci.yml`).
- **Release History**: See [CHANGELOG.md](CHANGELOG.md) (Semantic Versioning `v1.0.1`).
- **Community Standards**: See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **License**: Apache License 2.0 (`LICENSE`) for the open-source MCP connector client; statutory computation engines are commercial software licensed by **TITAN Capital Forensics LLC**, Albuquerque, New Mexico, USA (`audit@titancapitalforensics.com`).
