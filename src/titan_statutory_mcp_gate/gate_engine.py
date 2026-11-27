# SPDX-FileCopyrightText: 2026 TITAN Capital Forensics LLC
#
# SPDX-License-Identifier: Apache-2.0

"""
TITAN Capital Forensics LLC — Stateless Statutory Diagnostic Gate Engine
========================================================================
Zero-Secret, Zero-PII, Stateless Applicability, Schema Readiness & Cryptographic
Workpaper Hash Verification Gate.

Constitutional Boundaries Enforced:
- Pure English corporate surface (no Arabic text).
- Zero Freebies Law: Public MCP never runs full paid tax/duty/carbon calculations,
  never computes exact refund/deduction dollar outputs, and never emits filing
  workpapers (Form 7205, CBP 7551, CBAM XML, EUDR GeoJSON repairs, or 320-objective
  CMMC SSP/POA&M packs). It returns deterministic applicability flags, statutory
  citations, exposure tiers, and official checkout / Chamber-25 Partner Desk links.
- Immutable Pricing & Jurisdiction: Registered in Albuquerque, New Mexico, USA.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_NAME = "com.titancapitalforensics/statutory-gate"
SERVER_TITLE = "TITAN Statutory Gate"
SERVER_VERSION = "1.0.1"

ENTITY_LEGAL_NAME = "TITAN Capital Forensics LLC"
ENTITY_JURISDICTION = "Albuquerque, New Mexico, USA"
CONTACT_EMAIL = "audit@titancapitalforensics.com"

# Public Ed25519 Authority Verification Key (zero private keys ever stored here)
TITAN_AUTHORITY_PUB_RAW_B64 = "Ub3/lGEK5NXfeyoxdb11R7s06hPixx4FLnzHQyAPJnc="
TITAN_AUTHORITY_PUB_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAUb3/lGEK5NXfeyoxdb11R7s06hPixx4FLnzHQyAPJnc=\n"
    "-----END PUBLIC KEY-----"
)
TITAN_PUBKEY_URL = "https://titancapitalforensics.com/.well-known/titan-ed25519-pub.pem"

# Public non-sensitive release integrity digests from titancapitalforensics.com/seal/status.json
PUBLIC_SEAL_DIGESTS: dict[str, str] = {
    "64cf28a5ba57f70ffe2dfc8bb47da8bccb90ea87dcac469afc9b22e0116afce4": "TITAN-TRUST-SEAL-STATUS-v16.1 (Master Seal Registry 2026-Q4)",
    "ee365053a4b2ee9002e378d872028b59f685f163a146aa763afea5fadbcc2737": "PTNR-179D-SHIELD-2026Q4",
    "46795d3a6f1cdbd2fc41c5428ffe624ba041dd4907f703a2b550d4eda98e7ee4": "PTNR-CBAM-SOVEREIGN-2026Q4",
    "8d8381611a2fc8526e0c29dae744d3c2b0b0d0844a0145a9fdf82b0a4daf7b76": "PTNR-CISO-SECURITY-COMMAND-2026Q4",
    "b07e47fe604ac28a6ed60453e8c2f309c33da5e83295cba661ad0728f7d93347": "PTNR-DRAWBACK-SOVEREIGN-2026Q4",
    "6a59ef02508679ff7fa30fe86792ce68f910ba720023ad56a19f6dc7d61dffaf": "PTNR-EUDR-TRACE-2026Q4",
    "77c2ff29cefe60d3e22cd2f3c745baa2928de7d36d437f8752701552a66bb635": "PTNR-GDPR-CROSS-BORDER-DPO-2026Q4",
    "1b895ccc51668d1a8e6ab0a59d9f485e7870be5ec8aa7b3e9be15847f00bbaca": "PTNR-ICV-SOVEREIGN-2026Q4",
    "b1bbac6424dc748bcd9967b650b841637d1bd1fa21024b93b1314516fd32f1b6": "PTNR-QFZP-SHIELD-2026Q4",
    "e9f8161a56ed11e65826b38555839f4ea981390dd00a890cc0f62a3998bdc425": "PTNR-SCRIBEGUARD-CLINICAL-AI-2026Q4",
    "fd3b659d1ea915bf5a23327e644382b16a509ee5d1446db7e2ab377ad006dcc4": "PTNR-TENDER-SNIPER-2026Q4",
}

PORTAL_CATALOG: dict[str, dict[str, Any]] = {
    "drawback": {
        "domain": "drawbacksovereign.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 3950,
        "checkout_url": "https://drawbacksovereign.com/?gate=cbp-1313#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://drawbacksovereign.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "cbam": {
        "domain": "cbamsovereign.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2950,
        "checkout_url": "https://cbamsovereign.com/?gate=cbam-956#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://cbamsovereign.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "eudr": {
        "domain": "eudrpolygon.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2495,
        "checkout_url": "https://eudrpolygon.com/?gate=eudr-1115#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://eudrpolygon.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "179d": {
        "domain": "179dshield.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2495,
        "checkout_url": "https://179dshield.com/?gate=irc-179d#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://179dshield.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "cmmc": {
        "domain": "cisopass.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2495,
        "checkout_url": "https://cisopass.com/?gate=cmmc-800-171#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://cisopass.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "qfzp": {
        "domain": "qfzpshield.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 1495,
        "checkout_url": "https://qfzpshield.com/?gate=uae-qfzp#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://qfzpshield.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "gdpr": {
        "domain": "getgdprkit.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 1950,
        "checkout_url": "https://getgdprkit.com/?gate=gdpr-35#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://getgdprkit.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "verify": {
        "domain": "titancapitalforensics.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 4950,
        "checkout_url": "https://titancapitalforensics.com/?gate=verify#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://titancapitalforensics.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "icv": {
        "domain": "icvscorecard.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2495,
        "checkout_url": "https://icvscorecard.com/?gate=icv#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://icvscorecard.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "workflow": {
        "domain": "getworkflowkit.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 1950,
        "checkout_url": "https://getworkflowkit.com/?gate=workflow#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://getworkflowkit.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "rfp": {
        "domain": "rfpsniper.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2950,
        "checkout_url": "https://rfpsniper.com/?gate=rfp#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://rfpsniper.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "drm": {
        "domain": "titandrm.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 2950,
        "checkout_url": "https://titandrm.com/?gate=c2pa#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://titandrm.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "scribeguard": {
        "domain": "titan-scribeguard.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 1950,
        "checkout_url": "https://titan-scribeguard.com/?gate=hipaa#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://titan-scribeguard.com/?tier=partner#titan-enterprise-checkout-modal",
    },
    "trustcenter": {
        "domain": "titantrustcenter.com",
        "single_filing_usd": 495,
        "practice_annual_usd": 1950,
        "checkout_url": "https://titantrustcenter.com/?gate=soc2#titan-enterprise-checkout-modal",
        "partner_desk_url": "https://titantrustcenter.com/?tier=partner#titan-enterprise-checkout-modal",
    },
}

CHAMBER_25_SPEC = "$295/mo Practice Retainer + $145/wholesale client stamp (Chamber-25 Partner Desk)"

FREEBIE_KEY_PATTERNS = re.compile(
    r"(free_?calc|exact_?refund|exact_?deduction|output_?workpaper|generate_?form|"
    r"generate_?xml|bypass_?checkout|bypass_?paywall|decrypt_?tdrm|mint_?license|"
    r"private_?key|full_?report|line_?by_?line|dump_?prompt|system_?prompt)",
    re.IGNORECASE,
)

FREEBIE_TEXT_PATTERNS = re.compile(
    r"(?:calculate|compute|estimate)\s+(?:my|our|the|exact)?[\w\s$-]{0,30}"
    r"(?:tax|duty|refund|deduction|liability|penalty|carbon|co2e?|fee|cbam|179d)"
    r"|exact\s+(?:dollar|usd|eur|aed|tax|duty|refund|deduction|carbon|co2e?)"
    r"|(?:export|output|generate|produce|create|build|emit|write)\s+"
    r"(?:full|complete|signed|repaired|a|my|the)?[\w\s-]{0,25}"
    r"(?:workpaper|audit\s+pack|csv|xml|pdf|tax\s+return|form\s*7205|form\s*7551|geojson|dpia|ropa|ssp)"
    r"|full\s+(?:workpaper|audit\s+pack|report|schedule|filing)|line[- ]by[- ]line"
    r"|form\s*7205|form\s*7551|cbam[\w\s]{0,16}xml|repair(?:ed)?\s+geojson"
    r"|for\s+free|without\s+paying|bypass\s+(?:checkout|paywall|gate)"
    r"|\bfree(?!\s*[- ]?zone\b)\b[\w\s-]{0,20}(?:workpaper|calc|tax\s+return|refund|deduction|csv|xml|form\s*\d+)"
    r"|ignore\s+(?:previous|all|your|prior)\s+instructions|system\s+prompt|private\s+key"
    r"|decrypt\s+\.?tdrm|mint\s+(?:a\s+)?license",
    re.IGNORECASE,
)

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

CBAM_MASS_PREFIXES = (
    "25070080", "2523",
    "2808", "2814", "283421", "3102", "3105",
    "7201", "7203", "7204", "7205", "7206", "7207", "7208", "7209", "7210",
    "7211", "7212", "7213", "7214", "7215", "7216", "7217", "7218", "7219",
    "7220", "7221", "7222", "7223", "7224", "7225", "7226", "7227", "7228", "7229",
    "7301", "7302", "7303", "7304", "7305", "7306", "7307", "7308", "7309", "7310",
    "7311", "7318", "7326",
    "7601", "7603", "7604", "7605", "7606", "7607", "7608", "7609", "7610",
    "7611", "7612", "7613", "7614", "7616",
)
CBAM_NON_MASS_EXEMPT_PREFIXES = ("2716", "280410")
EUDR_PREFIXES = (
    "0102", "0201", "0202", "0901", "1201", "1207", "1208",
    "1507", "1511", "1513", "1801", "1802", "1803", "1804", "1805", "1806",
    "2304", "3823", "4001", "4005", "4006", "4007", "4008", "4009", "4010",
    "4011", "4012", "4013", "4014", "4015", "4016", "4017",
    "4101", "4104", "4107", "44", "47", "48", "49", "9401", "9403",
)

# Compact tool catalog strictly < 1,500 total schema tokens
TOOLS: list[dict[str, Any]] = [{'name': 'check_cbp_drawback_eligibility', 'title': 'US CBP Duty Drawback Statutory Gate', 'description': 'Check US CBP duty drawback statutory scope, 8-digit HTSUS/Schedule B alignment, and 5-year lookback window readiness under 19 U.S.C. 1313. Read-only diagnostic gate; zero duty refund calculations.', 'annotations': {'title': 'US CBP Duty Drawback Statutory Gate', 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}, 'inputSchema': {'type': 'object', 'properties': {'provision': {'type': 'string', 'enum': ['1313_j1_direct', '1313_j2_substitution', '1313_a_b_manufacturing'], 'description': 'Statutory drawback subsection under 19 U.S.C. 1313 (j(1) direct unused, j(2) substitution, or a/b manufacturing).'}, 'import_htsus_8': {'type': 'string', 'description': '8-digit US HTSUS import tariff classification code (digits only or dotted).'}, 'export_schedule_b_8': {'type': 'string', 'description': '8-digit US Schedule B or HTSUS export classification code for substitution/direct check.'}, 'days_since_import': {'type': 'number', 'description': 'Elapsed calendar days since CBP import entry date (checked against the 1,825-day 5-year statutory bar).'}, 'accelerated_payment': {'type': 'boolean', 'description': 'Whether claimant requests 19 CFR 190.92 accelerated payment bond readiness check.'}, 'query_note': {'type': 'string', 'description': 'Optional non-sensitive context note for diagnostic scope triage.'}}}}, {'name': 'check_eu_cbam_eudr_mandate', 'title': 'EU CBAM & EUDR Statutory Scope Gate', 'description': 'Check EU CBAM (Regulation (EU) 2023/956 and 2025/2083 50-tonne threshold) and EUDR (Regulation (EU) 2023/1115) CN/HS scope and WGS84 polygon rules. Read-only diagnostic gate; zero emissions math.', 'annotations': {'title': 'EU CBAM & EUDR Statutory Scope Gate', 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}, 'inputSchema': {'type': 'object', 'properties': {'regime': {'type': 'string', 'enum': ['cbam', 'eudr', 'both'], 'description': "Target European Union border compliance regime to evaluate: 'cbam', 'eudr', or 'both'."}, 'cn_or_hs_code': {'type': 'string', 'description': '4-to-8 digit EU Combined Nomenclature (CN) or Harmonized System (HS) commodity code.'}, 'annual_mass_tonnes': {'type': 'number', 'description': 'Cumulative annual net mass imported into the EU customs territory in metric tonnes.'}, 'plot_hectares': {'type': 'number', 'description': 'Production plot area in hectares (triggers EUDR Art. 9 polygon vs point rule at 4.0 ha).'}, 'geojson_ring_closed': {'type': 'boolean', 'description': 'Whether the WGS84 GeoJSON exterior coordinate ring is topologically closed.'}, 'query_note': {'type': 'string', 'description': 'Optional non-sensitive context note for diagnostic scope triage.'}}, 'required': ['regime']}}, {'name': 'check_irs_179d_cmmc_readiness', 'title': 'IRS Section 179D & DoD CMMC 2.0 Readiness Gate', 'description': 'Check IRS Section 179D (Form 7205) energy-efficient commercial building scope and DoD CMMC 2.0 / NIST SP 800-171 SPRS readiness. Read-only diagnostic gate; zero tax deduction math.', 'annotations': {'title': 'IRS Section 179D & DoD CMMC 2.0 Readiness Gate', 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}, 'inputSchema': {'type': 'object', 'properties': {'mandate': {'type': 'string', 'enum': ['irs_179d', 'cmmc_sprs', 'both'], 'description': "US federal statutory mandate to screen: 'irs_179d', 'cmmc_sprs', or 'both'."}, 'building_sqft': {'type': 'number', 'description': 'Gross floor area of the commercial or tax-exempt building in square feet.'}, 'prevailing_wage_met': {'type': 'boolean', 'description': 'Whether IRA prevailing wage and apprenticeship requirements under 26 U.S.C. 179D(b)(3) are satisfied.'}, 'tax_exempt_allocation': {'type': 'boolean', 'description': 'Whether project claims a Section 179D(d)(3) designer allocation letter from a tax-exempt or government entity.'}, 'sprs_score': {'type': 'integer', 'description': 'Current DoD Supplier Performance Risk System (SPRS) NIST SP 800-171 score (-203 to 110).'}, 'handles_cui_or_fci': {'type': 'string', 'enum': ['none', 'fci', 'cui'], 'description': "Highest defense contract information sensitivity handled: 'none', 'fci' (Level 1), or 'cui' (Level 2+)."}, 'query_note': {'type': 'string', 'description': 'Optional non-sensitive context note for diagnostic scope triage.'}}, 'required': ['mandate']}}, {'name': 'check_uae_qfzp_gdpr_trigger', 'title': 'UAE QFZP De-Minimis & EU GDPR Trigger Gate', 'description': 'Check UAE Corporate Tax QFZP 0% de-minimis cliff (Federal Decree-Law 47/2022 & MD 265/2023) and EU GDPR Art. 3/30/35 triggers. Read-only diagnostic gate; zero tax liability math.', 'annotations': {'title': 'UAE QFZP De-Minimis & EU GDPR Trigger Gate', 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}, 'inputSchema': {'type': 'object', 'properties': {'regime': {'type': 'string', 'enum': ['uae_qfzp', 'gdpr', 'both'], 'description': "Statutory compliance regime to evaluate: 'uae_qfzp', 'gdpr', or 'both'."}, 'non_qualifying_pct': {'type': 'number', 'description': 'Percentage share of non-qualifying revenue out of total Free Zone revenue (0 to 100; 5% statutory cliff).'}, 'non_qualifying_aed': {'type': 'number', 'description': 'Annual non-qualifying revenue in UAE Dirhams (AED; checked against AED 5,000,000 de-minimis ceiling).'}, 'excluded_activity': {'type': 'boolean', 'description': 'Whether entity performs an excluded activity under UAE Ministerial Decision No. 265 of 2023.'}, 'eu_data_subjects': {'type': 'boolean', 'description': 'Whether organization processes personal data of individuals in the EU/EEA under GDPR Article 3.'}, 'high_risk_processing': {'type': 'boolean', 'description': 'Whether processing involves large-scale profiling, special categories, or systematic monitoring triggering GDPR Art. 35 DPIA.'}, 'query_note': {'type': 'string', 'description': 'Optional non-sensitive context note for diagnostic scope triage.'}}, 'required': ['regime']}}, {'name': 'verify_titan_ed25519_workpaper_hash', 'title': 'TITAN Ed25519 Cryptographic Workpaper Verifier', 'description': 'Verify SHA-256 digest and detached Ed25519 signature of a TITAN statutory workpaper against the published authority public key. Read-only offline cryptographic gate.', 'annotations': {'title': 'TITAN Ed25519 Cryptographic Workpaper Verifier', 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}, 'inputSchema': {'type': 'object', 'properties': {'workpaper_sha256': {'type': 'string', 'description': '64-character hexadecimal SHA-256 digest of the canonical TITAN workpaper artifact.'}, 'canonical_payload': {'type': 'string', 'description': 'Optional UTF-8 canonical JSON payload string to hash and verify against the Ed25519 signature.'}, 'signature_b64': {'type': 'string', 'description': 'Optional Base64-encoded 64-byte detached Ed25519 signature over canonical_payload.'}, 'authority_pub_b64': {'type': 'string', 'description': 'Optional Base64-encoded 32-byte Ed25519 public key override (defaults to published TITAN authority key).'}, 'query_note': {'type': 'string', 'description': 'Optional non-sensitive context note for audit log labeling.'}}}}]


class GateInputError(ValueError):
    """Structured fail-closed parameter validation error."""


def _detect_freebie_attempt(args: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for k, v in args.items():
        if isinstance(k, str) and FREEBIE_KEY_PATTERNS.search(k):
            reasons.append(f"blocked_parameter:{k}")
        if isinstance(v, str):
            if len(v) > 8192:
                raise GateInputError("Input string exceeds 8192-character stateless gate ceiling.")
            if FREEBIE_TEXT_PATTERNS.search(v):
                reasons.append(f"blocked_freebie_intent_in:{k}")
    return reasons


def _as_finite_float(val: Any, name: str, min_val: float | None = None, max_val: float | None = None) -> float | None:
    if val is None:
        return None
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise GateInputError(f"Parameter '{name}' must be a finite number.")
    f = float(val)
    if not math.isfinite(f):
        raise GateInputError(f"Parameter '{name}' must be finite (NaN/Inf rejected).")
    if min_val is not None and f < min_val:
        raise GateInputError(f"Parameter '{name}' must be >= {min_val}.")
    if max_val is not None and f > max_val:
        raise GateInputError(f"Parameter '{name}' must be <= {max_val}.")
    return f


def _as_bool(val: Any, name: str) -> bool | None:
    if val is None:
        return None
    if not isinstance(val, bool):
        raise GateInputError(f"Parameter '{name}' must be a boolean.")
    return val


def _as_str(val: Any, name: str, max_len: int = 256) -> str:
    if val is None:
        return ""
    if not isinstance(val, str):
        raise GateInputError(f"Parameter '{name}' must be a string.")
    if len(val) > max_len:
        raise GateInputError(f"Parameter '{name}' exceeds {max_len} characters.")
    return val.strip()


def _settlement_block(portal_key: str, gate_tag: str) -> dict[str, Any]:
    p = PORTAL_CATALOG[portal_key]
    return {
        "single_filing_usd": p["single_filing_usd"],
        "practice_copilot_annual_usd": p["practice_annual_usd"],
        "chamber25_partner_tier": CHAMBER_25_SPEC,
        "official_checkout_url": p["checkout_url"],
        "chamber25_partner_desk_url": p["partner_desk_url"],
        "gate_tag": gate_tag,
    }


def _wrap_verdict(
    tool_name: str,
    verdict: dict[str, Any],
    portal_keys: list[str],
    freebie_triggers: list[str],
) -> dict[str, Any]:
    canonical = json.dumps({"tool": tool_name, "verdict": verdict}, sort_keys=True, separators=(",", ":"))
    receipt_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    primary = portal_keys[0]
    out: dict[str, Any] = {
        "gate_version": "2026.11",
        "mode": "STATELESS_DIAGNOSTIC_GATE_ONLY",
        "entity": ENTITY_LEGAL_NAME,
        "jurisdiction": ENTITY_JURISDICTION,
        "zero_freebie_enforced": True,
        "paid_calculation_withheld": True,
        "freebie_request_refused": bool(freebie_triggers),
        **verdict,
        "settlement_routing": _settlement_block(primary, tool_name),
        "gate_receipt_sha256": receipt_sha256,
    }
    if len(portal_keys) > 1:
        out["secondary_settlement_routing"] = _settlement_block(portal_keys[1], tool_name)
    if freebie_triggers:
        out["refusal_notice"] = (
            "ZERO_FREEBIES_ENFORCED: Free tax, duty, carbon, or workpaper calculations are disabled on the public MCP gate. "
            "Use the official paid checkout or Chamber-25 Partner Desk URLs for deterministic 0-ULP BigInt computations and Ed25519-sealed deliverables."
        )
        out["refused_triggers"] = freebie_triggers
    return out


def _eval_cbp_drawback(args: dict[str, Any], freebie_triggers: list[str]) -> dict[str, Any]:
    provision = _as_str(args.get("provision") or "1313_j2_substitution", "provision", 64)
    if provision not in ("1313_j1_direct", "1313_j2_substitution", "1313_a_b_manufacturing"):
        raise GateInputError("Invalid 'provision'. Allowed: 1313_j1_direct, 1313_j2_substitution, 1313_a_b_manufacturing.")

    imp_raw = _as_str(args.get("import_htsus_8"), "import_htsus_8", 32)
    exp_raw = _as_str(args.get("export_schedule_b_8"), "export_schedule_b_8", 32)
    days = _as_finite_float(args.get("days_since_import"), "days_since_import", 0.0, 7300.0)
    accel = _as_bool(args.get("accelerated_payment"), "accelerated_payment")

    imp_digits = re.sub(r"[^0-9]", "", imp_raw)
    exp_digits = re.sub(r"[^0-9]", "", exp_raw)
    readiness_flags: list[str] = []

    if imp_raw and len(imp_digits) < 8:
        readiness_flags.append("INVALID_IMPORT_HTSUS_LT_8_DIGITS")
    if exp_raw and len(exp_digits) < 8:
        readiness_flags.append("INVALID_EXPORT_SCHEDULE_B_LT_8_DIGITS")

    if provision == "1313_j2_substitution":
        if len(imp_digits) >= 8 and len(exp_digits) >= 8:
            if imp_digits[:8] == exp_digits[:8]:
                readiness_flags.append("HTSUS_8_MATCH_CONFIRMED_CHECK_19CFR190_32_BASKET_RULE")
            else:
                readiness_flags.append("HTSUS_8_MISMATCH_INELIGIBLE_FOR_1313_J2_SUBSTITUTION")
        else:
            readiness_flags.append("HTSUS_8_AND_SCHEDULE_B_8_REQUIRED_FOR_SUBSTITUTION_GATE")

    if days is None:
        applicability = "PENDING_IMPORT_DATE_LOOKBACK_CHECK"
        exposure = "MEDIUM_VERIFY_5YR_TFTEA_WINDOW"
        readiness_flags.append("MISSING_DAYS_SINCE_IMPORT")
    elif days > 1825:
        applicability = "TIME_BARRED_PAST_5YR_TFTEA_LIMIT"
        exposure = "CRITICAL_STATUTORY_FORFEITURE"
        readiness_flags.append("EXCEEDS_1825_DAY_STATUTORY_CAP")
    elif days >= 1645:
        applicability = "IN_SCOPE_URGENT_CLIFF_LT_180_DAYS"
        exposure = "HIGH_IMMINENT_5YR_EXPIRY_CLIFF"
    else:
        applicability = "IN_SCOPE_ELIGIBLE_WINDOW"
        exposure = "HIGH_UNCLAIMED_DUTY_RECOVERY_OPPORTUNITY"

    if "HTSUS_8_MISMATCH_INELIGIBLE_FOR_1313_J2_SUBSTITUTION" in readiness_flags and applicability.startswith("IN_SCOPE"):
        applicability = "OUT_OF_SCOPE_SUBSTITUTION_8DIGIT_MISMATCH"
        exposure = "CRITICAL_ACE_REJECT_RISK"

    if accel is True:
        readiness_flags.append("REQUIRES_19CFR190_92_DRAWBACK_BOND_AND_CBP_7553_PRIOR_NOTICE")

    verdict = {
        "applicability_status": applicability,
        "exposure_tier": exposure,
        "statutory_citations": [
            "19 U.S.C. § 1313(j)(2) (TFTEA Substitution Unused Merchandise Drawback)",
            "19 U.S.C. § 1313(r)(1) (5-Year Statutory Filing Limit)",
            "19 CFR Part 190 / 19 CFR § 190.32 (8-Digit HTSUS & Schedule B Basket Rule)",
        ],
        "schema_readiness": readiness_flags or ["BASELINE_PARAMS_VALID_ACE_CATAIR_AUDIT_REQUIRED"],
        "compliance_note": "Verify Section 232/301 statutory restrictions and 'Other' 8-digit basket exclusions before filing CBP Form 7551.",
    }
    return _wrap_verdict("check_cbp_drawback_eligibility", verdict, ["drawback"], freebie_triggers)


def _eval_eu_cbam_eudr(args: dict[str, Any], freebie_triggers: list[str]) -> dict[str, Any]:
    regime = _as_str(args.get("regime"), "regime", 16).lower()
    if regime not in ("cbam", "eudr", "both"):
        raise GateInputError("Parameter 'regime' is required and must be 'cbam', 'eudr', or 'both'.")

    code = re.sub(r"[^0-9]", "", _as_str(args.get("cn_or_hs_code"), "cn_or_hs_code", 32))
    mass = _as_finite_float(args.get("annual_mass_tonnes"), "annual_mass_tonnes", 0.0, 1e9)
    hectares = _as_finite_float(args.get("plot_hectares"), "plot_hectares", 0.0, 1e8)
    ring_closed = _as_bool(args.get("geojson_ring_closed"), "geojson_ring_closed")

    citations: list[str] = []
    readiness: list[str] = []
    statuses: list[str] = []
    portals: list[str] = []
    exposure = "MODERATE_COMPLIANCE_CHECK"

    if regime in ("cbam", "both"):
        portals.append("cbam")
        citations.extend([
            "Regulation (EU) 2023/956 (EU Carbon Border Adjustment Mechanism)",
            "Regulation (EU) 2025/2083 (50-Tonne Cumulative Annual Mass Threshold)",
        ])
        is_non_mass_exempt = code.startswith(CBAM_NON_MASS_EXEMPT_PREFIXES) if code else False
        is_cbam_cn = is_non_mass_exempt or (code.startswith(CBAM_MASS_PREFIXES) if code else False)
        if not code:
            readiness.append("CBAM_CN8_CODE_MISSING")
            statuses.append("CBAM_PENDING_CN_CODE")
        elif not is_cbam_cn:
            statuses.append("CBAM_OUT_OF_SCOPE_ANNEX_I")
        elif is_non_mass_exempt:
            statuses.append("CBAM_IN_SCOPE_NO_50T_EXEMPTION")
            exposure = "HIGH_AUTHORISED_DECLARANT_MANDATORY"
        elif mass is None:
            statuses.append("CBAM_ANNEX_I_MATCH_MISSING_ANNUAL_TONNAGE")
            readiness.append("CBAM_ANNUAL_MASS_TONNES_REQUIRED_FOR_50T_GATE")
            exposure = "HIGH_THRESHOLD_UNVERIFIED"
        elif mass >= 50.0:
            statuses.append("CBAM_IN_SCOPE_EXCEEDS_50T_THRESHOLD")
            exposure = "CRITICAL_EUR_100_PER_TCO2E_DEFAULT_MARKUP_RISK"
            readiness.append("AUTHORISED_CBAM_DECLARANT_AND_XML_REQUIRED")
        elif mass >= 40.0:
            statuses.append("CBAM_BORDERLINE_50T_CLIFF_WARNING")
            exposure = "HIGH_CUMULATIVE_GROUP_IMPORT_BREACH_RISK"
        else:
            statuses.append("CBAM_EXEMPT_UNDER_50T_DE_MINIMIS_VERIFY_AGGREGATE")

    if regime in ("eudr", "both"):
        portals.append("eudr")
        citations.append("Regulation (EU) 2023/1115 (EU Deforestation Regulation Art. 9 & Art. 25)")
        is_eudr = code.startswith(EUDR_PREFIXES) if code else True
        if code and not is_eudr:
            statuses.append("EUDR_HS_OUT_OF_SCOPE_ANNEX_I")
        else:
            if hectares is not None and hectares > 4.0:
                if ring_closed is False:
                    statuses.append("EUDR_IN_SCOPE_GEOJSON_POLYGON_UNCLOSED_FAIL")
                    exposure = "CRITICAL_TRACES_NT_REJECT_AND_4PCT_TURNOVER_FINE_RISK"
                    readiness.append("PLOT_GT_4HA_REQUIRES_CLOSED_WGS84_POLYGON_RING")
                elif ring_closed is True:
                    statuses.append("EUDR_IN_SCOPE_POLYGON_TOPOLOGY_READY_VERIFY_CRS")
                    exposure = "HIGH_DDS_SUBMISSION_AND_CUTOFF_2020_PROOF_REQUIRED"
                else:
                    statuses.append("EUDR_IN_SCOPE_POLYGON_REQUIRED_GT_4HA")
                    readiness.append("GEOJSON_RING_CLOSED_CHECK_REQUIRED")
                    exposure = "HIGH_GEOLOCATION_REQUIRED"
            else:
                statuses.append("EUDR_IN_SCOPE_POINT_OR_POLYGON_VERIFY_HS")
                if ring_closed is False:
                    readiness.append("GEOJSON_RING_UNCLOSED_FLAGGED")
                if exposure == "MODERATE_COMPLIANCE_CHECK":
                    exposure = "HIGH_ART_25_PENALTY_UP_TO_4PCT_EU_TURNOVER"

    verdict = {
        "applicability_status": " | ".join(statuses),
        "exposure_tier": exposure,
        "statutory_citations": citations,
        "schema_readiness": readiness or ["SCHEMA_METADATA_CHECKED_SEALED_FILING_PENDING"],
    }
    return _wrap_verdict("check_eu_cbam_eudr_mandate", verdict, portals, freebie_triggers)


def _eval_irs_179d_cmmc(args: dict[str, Any], freebie_triggers: list[str]) -> dict[str, Any]:
    mandate = _as_str(args.get("mandate"), "mandate", 16).lower()
    if mandate not in ("irs_179d", "cmmc_sprs", "both"):
        raise GateInputError("Parameter 'mandate' is required and must be 'irs_179d', 'cmmc_sprs', or 'both'.")

    sqft = _as_finite_float(args.get("building_sqft"), "building_sqft", 0.0, 1e9)
    pw_met = _as_bool(args.get("prevailing_wage_met"), "prevailing_wage_met")
    alloc = _as_bool(args.get("tax_exempt_allocation"), "tax_exempt_allocation")
    sprs_raw = args.get("sprs_score")
    sprs: int | None = None
    if sprs_raw is not None:
        if isinstance(sprs_raw, bool) or not isinstance(sprs_raw, int):
            raise GateInputError("Parameter 'sprs_score' must be an integer between -203 and 110.")
        if sprs_raw < -203 or sprs_raw > 110:
            raise GateInputError("Parameter 'sprs_score' out of valid DoD NIST SP 800-171 range [-203, 110].")
        sprs = sprs_raw
    cui_fci = _as_str(args.get("handles_cui_or_fci") or "none", "handles_cui_or_fci", 16).lower()
    if cui_fci not in ("none", "fci", "cui"):
        raise GateInputError("Parameter 'handles_cui_or_fci' must be 'none', 'fci', or 'cui'.")

    citations: list[str] = []
    readiness: list[str] = []
    statuses: list[str] = []
    portals: list[str] = []
    exposure = "MODERATE_READINESS_CHECK"

    if mandate in ("irs_179d", "both"):
        portals.append("179d")
        citations.extend([
            "26 U.S.C. § 179D (Energy Efficient Commercial Buildings Deduction)",
            "IRS Form 7205 & IRS Notice 2022-48 / ASHRAE Standard 90.1",
        ])
        if sqft is None or sqft == 0:
            statuses.append("IRS_179D_PENDING_BUILDING_SQFT")
            readiness.append("BUILDING_SQFT_AND_ASHRAE_90_1_MODEL_REQUIRED")
        else:
            statuses.append("IRS_179D_IN_SCOPE_QUALIFYING_PROPERTY")
            exposure = "HIGH_5X_PREVAILING_WAGE_CLIFF" if pw_met is False else "HIGH_QUALIFIED_DEDUCTION_GATE"
        if pw_met is False:
            readiness.append("NON_PREVAILING_WAGE_REDUCES_TO_BASE_TIER_5X_CLIFF")
        if alloc is True:
            readiness.append("FORM_7205_AND_SIGNED_179D_D_3_ALLOCATION_LETTER_MANDATORY")

    if mandate in ("cmmc_sprs", "both"):
        portals.append("cmmc")
        citations.extend([
            "32 CFR Part 170 (CMMC 2.0 Program Final Rule)",
            "DFARS 252.204-7019 / 252.204-7020 & NIST SP 800-171A (320 Objectives)",
        ])
        if cui_fci == "cui":
            if sprs is None:
                statuses.append("CMMC_LEVEL_2_MANDATORY_SPRS_SCORE_MISSING")
                readiness.append("SPRS_SCORE_AND_320_OBJECTIVE_SSP_REQUIRED")
                exposure = "CRITICAL_DFARS_AWARD_ELIGIBILITY_BLOCK"
            elif sprs < 88:
                statuses.append("CMMC_LEVEL_2_INELIGIBLE_BELOW_80PCT_POAM_FLOOR")
                readiness.append("SPRS_LT_88_FAILS_32CFR170_21_CONDITIONAL_CERT_THRESHOLD")
                exposure = "CRITICAL_CONTRACT_DISQUALIFICATION_AND_FCA_RISK"
            elif sprs < 110:
                statuses.append("CMMC_LEVEL_2_CONDITIONAL_180_DAY_POAM_WINDOW")
                readiness.append("VERIFY_ZERO_5PT_OR_3PT_PROHIBITED_POAM_CONTROLS")
                exposure = "HIGH_180_DAY_POAM_CLOSEOUT_CLIFF"
            else:
                statuses.append("CMMC_LEVEL_2_FULL_CLAIM_VERIFY_320_OBJECTIVES")
                exposure = "MODERATE_C3PAO_EVIDENCE_ATTESTATION_REQUIRED"
        elif cui_fci == "fci":
            statuses.append("CMMC_LEVEL_1_FAR_52_204_21_ANNUAL_SELF_AFFIRMATION")
        else:
            statuses.append("CMMC_NO_FCI_CUI_DECLARED_VERIFY_CONTRACT_FLOWDOWN")

    verdict = {
        "applicability_status": " | ".join(statuses),
        "exposure_tier": exposure,
        "statutory_citations": citations,
        "schema_readiness": readiness or ["ELIGIBILITY_GATES_CHECKED_PAID_WORKPAPER_REQUIRED"],
    }
    return _wrap_verdict("check_irs_179d_cmmc_readiness", verdict, portals, freebie_triggers)


def _eval_uae_qfzp_gdpr(args: dict[str, Any], freebie_triggers: list[str]) -> dict[str, Any]:
    regime = _as_str(args.get("regime"), "regime", 16).lower()
    if regime not in ("uae_qfzp", "gdpr", "both"):
        raise GateInputError("Parameter 'regime' is required and must be 'uae_qfzp', 'gdpr', or 'both'.")

    nq_pct = _as_finite_float(args.get("non_qualifying_pct"), "non_qualifying_pct", 0.0, 100.0)
    nq_aed = _as_finite_float(args.get("non_qualifying_aed"), "non_qualifying_aed", 0.0, 1e13)
    excluded = _as_bool(args.get("excluded_activity"), "excluded_activity")
    eu_subjects = _as_bool(args.get("eu_data_subjects"), "eu_data_subjects")
    high_risk = _as_bool(args.get("high_risk_processing"), "high_risk_processing")

    citations: list[str] = []
    readiness: list[str] = []
    statuses: list[str] = []
    portals: list[str] = []
    exposure = "MODERATE_STATUTORY_SCREEN"

    if regime in ("uae_qfzp", "both"):
        portals.append("qfzp")
        citations.extend([
            "UAE Federal Decree-Law No. 47 of 2022 (Art. 18 Qualifying Free Zone Person)",
            "UAE Cabinet Decision No. 100 of 2023 & Ministerial Decision No. 265 of 2023",
        ])
        breach_pct = nq_pct is not None and nq_pct > 5.0
        breach_aed = nq_aed is not None and nq_aed > 5_000_000.0
        near_cliff = (nq_pct is not None and 4.0 <= nq_pct <= 5.0) or (nq_aed is not None and 4_000_000.0 <= nq_aed <= 5_000_000.0)
        if excluded is True or breach_pct or breach_aed:
            statuses.append("UAE_QFZP_CLIFF_BREACHED_5YR_9PCT_DISQUALIFICATION")
            exposure = "CRITICAL_0PCT_LOSS_FOR_CURRENT_PLUS_4_TAX_PERIODS"
            if excluded is True:
                readiness.append("MD_265_2023_EXCLUDED_ACTIVITY_DETECTED")
            if breach_pct or breach_aed:
                readiness.append("EXCEEDS_LOWER_OF_5PCT_OR_AED_5M_DE_MINIMIS_CAP")
        elif near_cliff:
            statuses.append("UAE_QFZP_BORDERLINE_DE_MINIMIS_CLIFF_WARNING")
            exposure = "HIGH_IMMINENT_5YR_LOCKOUT_PROXIMITY"
        else:
            statuses.append("UAE_QFZP_ELIGIBLE_VERIFY_ADEQUATE_SUBSTANCE_AND_AUDITED_FS")
            readiness.append("REQUIRES_AUDITED_FINANCIAL_STATEMENTS_AND_SUBSTANCE_PROOF")

    if regime in ("gdpr", "both"):
        portals.append("gdpr")
        citations.append("Regulation (EU) 2016/679 (GDPR Art. 3, Art. 30, Art. 35, Art. 83(5))")
        if eu_subjects is False:
            statuses.append("GDPR_ART_3_OUT_OF_TERRITORIAL_SCOPE_VERIFY_PROCESSORS")
        elif high_risk is True:
            statuses.append("GDPR_IN_SCOPE_ART_35_DPIA_AND_ART_30_ROPA_MANDATORY")
            if not exposure.startswith("CRITICAL"):
                exposure = "CRITICAL_UP_TO_4PCT_GLOBAL_TURNOVER_OR_EUR_20M"
            readiness.append("MANDATORY_DPIA_BEFORE_PROCESSING_AND_ART_27_REP_CHECK")
        else:
            statuses.append("GDPR_IN_SCOPE_ART_30_ROPA_AND_TIA_SCREEN_REQUIRED")
            if exposure == "MODERATE_STATUTORY_SCREEN":
                exposure = "HIGH_SUPERVISORY_AUDIT_READINESS_REQUIRED"

    verdict = {
        "applicability_status": " | ".join(statuses),
        "exposure_tier": exposure,
        "statutory_citations": citations,
        "schema_readiness": readiness or ["PRELIMINARY_THRESHOLD_CHECKED"],
    }
    return _wrap_verdict("check_uae_qfzp_gdpr_trigger", verdict, portals, freebie_triggers)


def _verify_ed25519_workpaper(args: dict[str, Any], freebie_triggers: list[str]) -> dict[str, Any]:
    sha_in = _as_str(args.get("workpaper_sha256"), "workpaper_sha256", 128).lower()
    payload = _as_str(args.get("canonical_payload"), "canonical_payload", 8192)
    sig_b64 = _as_str(args.get("signature_b64"), "signature_b64", 512)
    pub_b64 = _as_str(args.get("authority_pub_b64"), "authority_pub_b64", 256)

    if not sha_in and not payload:
        raise GateInputError("Provide at least 'workpaper_sha256' (64-hex) or 'canonical_payload'.")

    if sha_in and not SHA256_RE.match(sha_in):
        raise GateInputError("Parameter 'workpaper_sha256' must be a valid 64-character hexadecimal SHA-256 digest.")

    computed_payload_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest() if payload else None
    effective_sha256 = sha_in or (computed_payload_sha256 or "")

    payload_hash_match: bool | None = None
    if sha_in and computed_payload_sha256 is not None:
        payload_hash_match = (sha_in == computed_payload_sha256)
        if not payload_hash_match:
            verdict = {
                "applicability_status": "SHA256_PAYLOAD_MISMATCH_TAMPER_DETECTED",
                "exposure_tier": "CRITICAL_INTEGRITY_FAILURE",
                "verified_cryptographically": False,
                "supplied_sha256": sha_in,
                "computed_payload_sha256": computed_payload_sha256,
                "authority_public_key_ed25519_b64": TITAN_AUTHORITY_PUB_RAW_B64,
                "authority_public_key_url": TITAN_PUBKEY_URL,
                "statutory_citations": ["RFC 8032 (Ed25519)", "RFC 8785 (JSON Canonicalization Scheme)", "FIPS 180-4 (SHA-256)"],
                "schema_readiness": ["HASH_MISMATCH_REJECTED_FAIL_CLOSED"],
            }
            return _wrap_verdict("verify_titan_ed25519_workpaper_hash", verdict, ["verify"], freebie_triggers)

    registry_match = PUBLIC_SEAL_DIGESTS.get(effective_sha256)
    using_official_key = (not pub_b64) or (pub_b64 == TITAN_AUTHORITY_PUB_RAW_B64)
    key_b64 = pub_b64 or TITAN_AUTHORITY_PUB_RAW_B64

    sig_status = "HASH_FORMAT_VALID_SIGNATURE_NOT_SUPPLIED"
    verified_crypto = False
    matched_preimage = None

    if sig_b64:
        try:
            pub_bytes = base64.b64decode(key_b64, validate=True)
            if len(pub_bytes) == 44 and pub_bytes[:12] == bytes.fromhex("302a300506032b6570032100"):
                pub_bytes = pub_bytes[12:]
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as exc:
            raise GateInputError(f"Invalid Ed25519 public key format: {exc}") from exc

        try:
            sig_bytes = base64.b64decode(sig_b64, validate=True)
            if len(sig_bytes) != 64:
                raise ValueError("Ed25519 signature must decode to exactly 64 bytes.")
        except Exception as exc:
            raise GateInputError(f"Invalid Base64 Ed25519 signature: {exc}") from exc

        candidates: list[tuple[str, bytes]] = []
        if payload:
            candidates.append(("canonical_payload_utf8", payload.encode("utf-8")))
        if effective_sha256:
            candidates.append(("sha256_hex_ascii", effective_sha256.encode("ascii")))
            candidates.append(("sha256_raw_32bytes", bytes.fromhex(effective_sha256)))

        for label, msg in candidates:
            try:
                pub_key.verify(sig_bytes, msg)
                verified_crypto = True
                matched_preimage = label
                break
            except InvalidSignature:
                continue

        sig_status = "ED25519_SIGNATURE_VERIFIED" if verified_crypto else "ED25519_SIGNATURE_INVALID_TAMPER_DETECTED"
    elif registry_match:
        sig_status = "PUBLIC_SEAL_DIGEST_MATCHED_PROVIDE_ED25519_SIG_FOR_FULL_PROOF"

    exposure = "LOW_AUTHENTIC_VERIFIED" if verified_crypto else (
        "CRITICAL_SIGNATURE_TAMPER_OR_KEY_MISMATCH" if sig_b64 else "MEDIUM_UNVERIFIED_DIGEST_ONLY"
    )

    verdict = {
        "applicability_status": sig_status,
        "exposure_tier": exposure,
        "verified_cryptographically": verified_crypto,
        "matched_preimage": matched_preimage,
        "official_titan_authority_key_used": using_official_key,
        "authority_public_key_ed25519_b64": key_b64,
        "authority_public_key_url": TITAN_PUBKEY_URL,
        "workpaper_sha256": effective_sha256,
        "payload_sha256_matched": payload_hash_match,
        "public_seal_registry_match": registry_match,
        "statutory_citations": ["RFC 8032 (Ed25519)", "RFC 8785 (JCS)", "FIPS 180-4 (SHA-256)"],
        "schema_readiness": [
            "ZERO_SECRET_PUBLIC_KEY_VERIFICATION_ACTIVE",
            "OFFLINE_VAULT_DELIVERY_URL: https://titancapitalforensics.com/vault-delivery/",
        ],
    }
    return _wrap_verdict("verify_titan_ed25519_workpaper_hash", verdict, ["verify"], freebie_triggers)


def call_tool(name: str, arguments: Any) -> dict[str, Any]:
    """Execute one of the 5 stateless diagnostic gate tools fail-closed."""
    if not isinstance(arguments, dict):
        raise GateInputError("Tool 'arguments' must be a JSON object.")

    freebie_triggers = _detect_freebie_attempt(arguments)

    dispatch = {
        "check_cbp_drawback_eligibility": _eval_cbp_drawback,
        "check_eu_cbam_eudr_mandate": _eval_eu_cbam_eudr,
        "check_irs_179d_cmmc_readiness": _eval_irs_179d_cmmc,
        "check_uae_qfzp_gdpr_trigger": _eval_uae_qfzp_gdpr,
        "verify_titan_ed25519_workpaper_hash": _verify_ed25519_workpaper,
    }
    fn = dispatch.get(name)
    if fn is None:
        raise KeyError(f"Unknown tool: {name}")
    return fn(arguments, freebie_triggers)


def handle_jsonrpc_message(msg: Any) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 request/notification. Returns None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        req_id = msg.get("id") if isinstance(msg, dict) else None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 Request"},
        }

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") if msg.get("params") is not None else {}

    # Notifications have no 'id' -> return None (HTTP 202 Accepted on Streamable HTTP)
    if "id" not in msg or req_id is None and str(method).startswith("notifications/"):
        return None

    if method == "initialize":
        req_ver = params.get("protocolVersion") if isinstance(params, dict) else None
        neg_ver = req_ver if req_ver in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": neg_ver,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "title": SERVER_TITLE,
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "Stateless statutory applicability, schema readiness, and Ed25519 hash verification gate "
                    "for TITAN Capital Forensics LLC (Albuquerque, New Mexico, USA). "
                    "Returns diagnostic verdicts, citations, and paid portal URLs only; zero calculations or workpapers."
                ),
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Invalid params: 'name' string is required"},
            }
        tool_name = params["name"]
        tool_args = params.get("arguments", {})
        try:
            verdict = call_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(verdict, indent=2)}],
                    "structuredContent": verdict,
                    "isError": False,
                },
            }
        except KeyError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": str(exc)},
            }
        except GateInputError as exc:
            err_payload = {
                "gate_version": "2026.11",
                "mode": "STATELESS_DIAGNOSTIC_GATE_ONLY",
                "zero_freebie_enforced": True,
                "error": "INVALID_DIAGNOSTIC_PARAMETERS",
                "detail": str(exc),
                "official_portal": "https://titancapitalforensics.com/",
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(err_payload, indent=2)}],
                    "structuredContent": err_payload,
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }
