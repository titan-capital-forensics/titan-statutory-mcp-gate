---
name: titan-statutory-gate
description: Deterministic, zero-egress statutory applicability, regulatory threshold, and cryptographic Ed25519 workpaper verification across US (IRS 179D, CBP Duty Drawback, DoD CMMC 2.0), EU (CBAM, EUDR, GDPR), and UAE (QFZP) via the TITAN Statutory Gate MCP server.
license: Apache-2.0
metadata:
  author: TITAN Capital Forensics LLC
  version: "1.0.1"
  homepage: https://titancapitalforensics.com/
  mcp_endpoint: https://mcp.titancapitalforensics.com/mcp
  mcp_registry: com.titancapitalforensics/statutory-gate
---

# TITAN Statutory Gate Skill

Use this skill whenever an enterprise workflow, compliance review, procurement check, or audit workbench needs **deterministic statutory applicability diagnostics**, **regulatory schema checklists**, or **cryptographic `Ed25519` workpaper seal verification** across US, EU, and UAE statutory frameworks with **zero PII transmission** and **zero credentials**.

## Quick Connection (Streamable HTTP MCP)

Connect your MCP-compatible agent (`Claude Code`, `Codex`, `Cursor`, `Antigravity`, `VS Code Copilot`, `OpenCode`) to the official stateless remote endpoint:

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

Or run the official PyPI bridge locally:

```bash
pip install titan-statutory-mcp-gate
titan-statutory-mcp-gate --probe-remote
```

## Available Deterministic Tools

1. **`check_cbp_drawback_eligibility`** — Evaluates `19 U.S.C. § 1313(j)(2)` / `19 CFR Part 190` substitution duty drawback scope, 8-digit HTSUS vs. Schedule B alignment, and the 5-year (`1,825`-day) TFTEA lookback window.
2. **`check_eu_cbam_eudr_mandate`** — Evaluates EU Definitive CBAM (`Regulation (EU) 2023/956` & `Regulation (EU) 2025/2083` 50-tonne cumulative threshold) and EU Deforestation Regulation (`Regulation (EU) 2023/1115` Art. 9 GeoJSON polygon rules).
3. **`check_irs_179d_cmmc_readiness`** — Evaluates `26 U.S.C. § 179D` (`IRS Form 7205` ASHRAE deduction & prevailing-wage 5x multiplier) and DoD `CMMC 2.0` / `NIST SP 800-171` (`32 CFR Part 170` SPRS floor & 180-day POA&M boundary).
4. **`check_uae_qfzp_gdpr_trigger`** — Evaluates UAE Corporate Tax Qualifying Free Zone Person `5%` / `AED 5,000,000` de-minimis threshold (`Federal Decree-Law No. 47 of 2022 Art. 18`) and EU GDPR `Art. 3 / 30 / 35` RoPA & DPIA mandates.
5. **`verify_titan_ed25519_workpaper_hash`** — Cryptographically verifies `SHA-256` digests and `Ed25519` authority signatures on official TITAN statutory audit dossiers against `https://titancapitalforensics.com/.well-known/titan-ed25519-pub.pem`.

## Verification & Governance Boundary

- **Zero Data Retention:** Never send client PII, raw tax IDs, or confidential source documents to the public diagnostic gate; send only numeric thresholds, dates, HTS/CN codes, and cryptographic SHA-256 digests.
- **Institutional Clearance:** Public MCP tools return deterministic applicability verdicts, official statutory citations, and schema checklists. Certified schedules, formal SMT-LIB v2 (Z3) proofs, regulator-ready filings, and sealed `Ed25519` workpapers are licensed separately through `https://titancapitalforensics.com/`.
- **Canonical Discovery:**
  - A2A Agent Card: `https://titancapitalforensics.com/.well-known/agent-card.json`
  - MCP Manifest: `https://mcp.titancapitalforensics.com/.well-known/mcp.json`
  - `llms.txt`: `https://titancapitalforensics.com/llms.txt`
  - Security Disclosure: `https://titancapitalforensics.com/.well-known/security.txt`
