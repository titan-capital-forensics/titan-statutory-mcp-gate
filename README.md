# TITAN Statutory Gate (`com.titancapitalforensics/statutory-gate`)

<!-- mcp-name: com.titancapitalforensics/statutory-gate -->

Stateless diagnostic statutory applicability, schema readiness, and Ed25519 workpaper hash verification MCP server operated by **TITAN Capital Forensics LLC** (Albuquerque, New Mexico, USA).

- **Remote Streamable HTTP MCP (`protocolVersion: "2025-06-18"`):** `https://mcp.titancapitalforensics.com/mcp`
- **Health Endpoint:** `https://mcp.titancapitalforensics.com/health`
- **Discovery Manifest:** `https://mcp.titancapitalforensics.com/.well-known/mcp.json`
- **Official Portal:** `https://titancapitalforensics.com/`

---

## Diagnostic Scope & Zero-Freebies Policy

This MCP server operates strictly as a **zero-secret, zero-PII, stateless diagnostic applicability gate**:

1. **`check_cbp_drawback_eligibility`** — Checks `19 U.S.C. § 1313(j)(2)` / `19 CFR Part 190` substitution drawback, 8-digit HTSUS vs Schedule B readiness, and the 5-year (`1,825`-day) TFTEA lookback window (`drawbacksovereign.com` — `$395` single filing | `$3,950/yr` Practice Co-Pilot | Chamber-25 `$295/mo + $145/stamp`).
2. **`check_eu_cbam_eudr_mandate`** — Checks EU CBAM (`Regulation (EU) 2023/956` & `Regulation (EU) 2025/2083` 50-tonne annual mass threshold) and EU EUDR (`Regulation (EU) 2023/1115` Art. 9 polygon closure vs `<= 4` ha rule) (`cbamsovereign.com` `$295` / `eudrpolygon.com` `$245` | Chamber-25 `$295/mo + $145/stamp`).
3. **`check_irs_179d_cmmc_readiness`** — Checks `26 U.S.C. § 179D` (`IRS Form 7205`, prevailing wage 5x cliff, tax-exempt designer allocation) and DoD `CMMC 2.0` / `NIST SP 800-171` (`32 CFR Part 170`, `SPRS` score floor & 180-day POA&M boundary) (`179dshield.com` `$295` / `cisopass.com` `$295` | Chamber-25 `$295/mo + $145/stamp`).
4. **`check_uae_qfzp_gdpr_trigger`** — Checks UAE Corporate Tax QFZP `5%` / `AED 5,000,000` de-minimis cliff (`Federal Decree-Law No. 47 of 2022 Art. 18`, `Cabinet Decision 100/2023`, `MD 265/2023`) and EU GDPR `Art. 3 / 30 / 35` DPIA trigger (`qfzpshield.com` `$149` / `getgdprkit.com` `$195` | Chamber-25 `$295/mo + $145/stamp`).
5. **`verify_titan_ed25519_workpaper_hash`** — Cryptographically verifies SHA-256 digests and Ed25519 signatures against TITAN's published authority public key (`https://titancapitalforensics.com/.well-known/titan-ed25519-pub.pem`) (`titancapitalforensics.com` `$495` | Chamber-25 `$295/mo + $145/stamp`).

No free tax, duty, carbon, or workpaper calculations are performed via the public MCP interface. Full deterministic `0-ULP BigInt` computations, Microsoft Z3 formal proofs, and `Ed25519`-sealed deliverables are executed client-side inside licensed TITAN portals.

---

## Connect Any MCP Client (Remote HTTPS — Zero Install)

Add to `.mcp.json` / `.cursor/mcp.json` / Claude Desktop:

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

Or run locally over `stdio`:

```bash
pip install .
titan-statutory-mcp-gate
```

---

## 1-Command Publish Instructions Across Official Registries

### 1. Official MCP Registry (`registry.modelcontextprotocol.io` v0.1 — `com.titancapitalforensics/statutory-gate`)

Domain namespace `com.titancapitalforensics/*` uses Official Registry HTTP or apex DNS verification (`v=MCPv1; k=ed25519; p=<base64_pub>` on `titancapitalforensics.com` apex TXT or `https://titancapitalforensics.com/.well-known/mcp-registry-auth`).

```bash
# Install mcp-publisher (macOS Homebrew)
brew install mcp-publisher

# Validate server.json locally against 2025-12-11 schema
mcp-publisher validate server.json

# Generate dedicated Ed25519 registry signing key (requires OpenSSL 3) and login via DNS/HTTP proof, then publish:
/opt/homebrew/opt/openssl@3/bin/openssl genpkey -algorithm Ed25519 -out /tmp/mcp_reg_key.pem && \
echo "v=MCPv1; k=ed25519; p=$(/opt/homebrew/opt/openssl@3/bin/openssl pkey -in /tmp/mcp_reg_key.pem -pubout -outform DER | tail -c 32 | base64)" && \
# Place the printed TXT record at apex titancapitalforensics.com (or /.well-known/mcp-registry-auth), then:
MCP_PRIVATE_KEY="$(/opt/homebrew/opt/openssl@3/bin/openssl pkey -in /tmp/mcp_reg_key.pem -noout -text | sed -n '/priv:/,/pub:/p' | sed '1d;$d' | tr -d ' :\n')" \
  mcp-publisher login dns --domain titancapitalforensics.com && \
mcp-publisher publish server.json
```

*(Note: After publishing this package to PyPI via `python3 -m build && twine upload dist/*`, add `"packages": [{"registryType": "pypi", "identifier": "titan-statutory-mcp-gate", "version": "1.0.0", "transport": {"type": "stdio"}}]` to `server.json` before re-publishing; `<!-- mcp-name: com.titancapitalforensics/statutory-gate -->` is already embedded above.)*

### 2. Cursor Directory (`cursor.directory/plugins/new`)

1. Push this directory to `https://github.com/titan-capital-forensics/titan-statutory-mcp-gate` (includes `.mcp.json` and `glama.json`):
   ```bash
   git init && git add . && git commit -m "Initial release: com.titancapitalforensics/statutory-gate v1.0.0" && git remote add origin https://github.com/titan-capital-forensics/titan-statutory-mcp-gate.git && git push -u origin main
   ```
2. Sign in at `https://cursor.directory/plugins/new` with GitHub and submit `https://github.com/titan-capital-forensics/titan-statutory-mcp-gate` (auto-reads `.mcp.json`).

### 3. `mcp.so` (`https://mcp.so/submit`)

Submit directly at `https://mcp.so/submit` using:
- **Repository URL:** `https://github.com/titan-capital-forensics/titan-statutory-mcp-gate`
- **Remote MCP Endpoint:** `https://mcp.titancapitalforensics.com/mcp`

### 4. Glama & `awesome-remote-mcp-servers` (`punkpeye/awesome-remote-mcp-servers`)

1. Claim `https://github.com/titan-capital-forensics/titan-statutory-mcp-gate` at `https://glama.ai/mcp/servers` (`glama.json` is included at repo root) to generate the verified Glama connector badge SVG.
2. Fork `punkpeye/awesome-remote-mcp-servers`, append the single entry below under **Legal / Compliance / Finance** (with live Glama badge + `🔓` unauthenticated `initialize`), and open PR titled `Add TITAN Statutory Gate (🤖🤖🤖)`:
   ```markdown
   - [TITAN Statutory Gate](https://mcp.titancapitalforensics.com/mcp) 🔓 [![Glama](https://glama.ai/mcp/servers/titan-capital-forensics/titan-statutory-mcp-gate/badge.svg)](https://glama.ai/mcp/servers/titan-capital-forensics/titan-statutory-mcp-gate) - Stateless US/EU/UAE statutory applicability, schema readiness, and Ed25519 workpaper hash gate.
   ```
