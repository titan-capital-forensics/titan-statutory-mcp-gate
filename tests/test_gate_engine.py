# SPDX-FileCopyrightText: 2026 TITAN Capital Forensics LLC
#
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive automated test suite for TITAN Statutory Gate MCP server & CLI."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from titan_statutory_mcp_gate.cli import main, probe_remote, run_stdio_server
from titan_statutory_mcp_gate.gate_engine import (
    PROTOCOL_VERSION,
    PUBLIC_SEAL_DIGESTS,
    SERVER_NAME,
    SERVER_VERSION,
    TOOLS,
    GateInputError,
    call_tool,
    handle_jsonrpc_message,
)


def test_version_and_tool_catalog_integrity() -> None:
    assert SERVER_NAME == "com.titancapitalforensics/statutory-gate"
    assert SERVER_VERSION == "1.0.1"
    assert len(TOOLS) == 5
    names = {t["name"] for t in TOOLS}
    assert names == {
        "check_cbp_drawback_eligibility",
        "check_eu_cbam_eudr_mandate",
        "check_irs_179d_cmmc_readiness",
        "check_uae_qfzp_gdpr_trigger",
        "verify_titan_ed25519_workpaper_hash",
    }


def test_cbp_drawback_eligible_mismatch_and_time_barred() -> None:
    eligible = call_tool(
        "check_cbp_drawback_eligibility",
        {
            "provision": "1313_j2_substitution",
            "import_htsus_8": "7208.10.15",
            "export_schedule_b_8": "7208.10.15",
            "days_since_import": 400,
            "accelerated_payment": True,
        },
    )
    assert eligible["applicability_status"] == "IN_SCOPE_ELIGIBLE_WINDOW"
    assert "HTSUS_8_MATCH_CONFIRMED_CHECK_19CFR190_32_BASKET_RULE" in eligible["schema_readiness"]
    assert "REQUIRES_19CFR190_92_DRAWBACK_BOND_AND_CBP_7553_PRIOR_NOTICE" in eligible["schema_readiness"]
    assert len(eligible["gate_receipt_sha256"]) == 64

    mismatch = call_tool(
        "check_cbp_drawback_eligibility",
        {
            "provision": "1313_j2_substitution",
            "import_htsus_8": "72081015",
            "export_schedule_b_8": "76011000",
            "days_since_import": 500,
        },
    )
    assert mismatch["applicability_status"] == "OUT_OF_SCOPE_SUBSTITUTION_8DIGIT_MISMATCH"

    urgent = call_tool("check_cbp_drawback_eligibility", {"days_since_import": 1700})
    assert urgent["applicability_status"] == "IN_SCOPE_URGENT_CLIFF_LT_180_DAYS"

    barred = call_tool("check_cbp_drawback_eligibility", {"days_since_import": 1900})
    assert barred["applicability_status"] == "TIME_BARRED_PAST_5YR_TFTEA_LIMIT"

    pending = call_tool("check_cbp_drawback_eligibility", {})
    assert pending["applicability_status"] == "PENDING_IMPORT_DATE_LOOKBACK_CHECK"


def test_eu_cbam_and_eudr_mandates() -> None:
    cbam_high = call_tool(
        "check_eu_cbam_eudr_mandate",
        {"regime": "cbam", "cn_or_hs_code": "72081000", "annual_mass_tonnes": 120.5},
    )
    assert cbam_high["applicability_status"] == "CBAM_IN_SCOPE_EXCEEDS_50T_THRESHOLD"

    cbam_border = call_tool(
        "check_eu_cbam_eudr_mandate",
        {"regime": "cbam", "cn_or_hs_code": "76011000", "annual_mass_tonnes": 45.0},
    )
    assert cbam_border["applicability_status"] == "CBAM_BORDERLINE_50T_CLIFF_WARNING"

    cbam_exempt = call_tool(
        "check_eu_cbam_eudr_mandate",
        {"regime": "cbam", "cn_or_hs_code": "76011000", "annual_mass_tonnes": 12.0},
    )
    assert cbam_exempt["applicability_status"] == "CBAM_EXEMPT_UNDER_50T_DE_MINIMIS_VERIFY_AGGREGATE"

    cbam_elec = call_tool(
        "check_eu_cbam_eudr_mandate",
        {"regime": "cbam", "cn_or_hs_code": "27160000", "annual_mass_tonnes": 1.0},
    )
    assert cbam_elec["applicability_status"] == "CBAM_IN_SCOPE_NO_50T_EXEMPTION"

    eudr_unclosed = call_tool(
        "check_eu_cbam_eudr_mandate",
        {
            "regime": "eudr",
            "cn_or_hs_code": "09011100",
            "plot_hectares": 12.0,
            "geojson_ring_closed": False,
        },
    )
    assert eudr_unclosed["applicability_status"] == "EUDR_IN_SCOPE_GEOJSON_POLYGON_UNCLOSED_FAIL"

    both = call_tool(
        "check_eu_cbam_eudr_mandate",
        {"regime": "both", "cn_or_hs_code": "44071100", "plot_hectares": 6.0, "geojson_ring_closed": True},
    )
    assert "secondary_settlement_routing" in both


def test_irs_179d_and_cmmc_readiness() -> None:
    res = call_tool(
        "check_irs_179d_cmmc_readiness",
        {
            "mandate": "both",
            "building_sqft": 75000,
            "prevailing_wage_met": False,
            "tax_exempt_allocation": True,
            "handles_cui_or_fci": "cui",
            "sprs_score": 72,
        },
    )
    assert "IRS_179D_IN_SCOPE_QUALIFYING_PROPERTY" in res["applicability_status"]
    assert "CMMC_LEVEL_2_INELIGIBLE_BELOW_80PCT_POAM_FLOOR" in res["applicability_status"]
    assert "NON_PREVAILING_WAGE_REDUCES_TO_BASE_TIER_5X_CLIFF" in res["schema_readiness"]
    assert "FORM_7205_AND_SIGNED_179D_D_3_ALLOCATION_LETTER_MANDATORY" in res["schema_readiness"]

    cond = call_tool(
        "check_irs_179d_cmmc_readiness",
        {"mandate": "cmmc_sprs", "handles_cui_or_fci": "cui", "sprs_score": 95},
    )
    assert cond["applicability_status"] == "CMMC_LEVEL_2_CONDITIONAL_180_DAY_POAM_WINDOW"

    full = call_tool(
        "check_irs_179d_cmmc_readiness",
        {"mandate": "cmmc_sprs", "handles_cui_or_fci": "cui", "sprs_score": 110},
    )
    assert full["applicability_status"] == "CMMC_LEVEL_2_FULL_CLAIM_VERIFY_320_OBJECTIVES"


def test_uae_qfzp_and_gdpr_triggers() -> None:
    breach = call_tool(
        "check_uae_qfzp_gdpr_trigger",
        {
            "regime": "both",
            "non_qualifying_pct": 5.5,
            "non_qualifying_aed": 6_000_000,
            "excluded_activity": True,
            "eu_data_subjects": True,
            "high_risk_processing": True,
        },
    )
    assert "UAE_QFZP_CLIFF_BREACHED_5YR_9PCT_DISQUALIFICATION" in breach["applicability_status"]
    assert "GDPR_IN_SCOPE_ART_35_DPIA_AND_ART_30_ROPA_MANDATORY" in breach["applicability_status"]

    near = call_tool(
        "check_uae_qfzp_gdpr_trigger",
        {"regime": "uae_qfzp", "non_qualifying_pct": 4.5, "non_qualifying_aed": 1_000_000},
    )
    assert near["applicability_status"] == "UAE_QFZP_BORDERLINE_DE_MINIMIS_CLIFF_WARNING"

    ok_qfzp = call_tool(
        "check_uae_qfzp_gdpr_trigger",
        {"regime": "uae_qfzp", "non_qualifying_pct": 1.2, "non_qualifying_aed": 500_000},
    )
    assert ok_qfzp["applicability_status"] == "UAE_QFZP_ELIGIBLE_VERIFY_ADEQUATE_SUBSTANCE_AND_AUDITED_FS"


def test_ed25519_verification_valid_invalid_and_tamper() -> None:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")

    payload = '{"entity":"TITAN Capital Forensics LLC","seal":"ok"}'
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    sig_b64 = base64.b64encode(priv.sign(payload.encode("utf-8"))).decode("ascii")

    verified = call_tool(
        "verify_titan_ed25519_workpaper_hash",
        {
            "workpaper_sha256": digest,
            "canonical_payload": payload,
            "signature_b64": sig_b64,
            "authority_pub_b64": pub_b64,
        },
    )
    assert verified["verified_cryptographically"] is True
    assert verified["applicability_status"] == "ED25519_SIGNATURE_VERIFIED"
    assert verified["matched_preimage"] == "canonical_payload_utf8"

    # Tampered signature
    bad_sig = base64.b64encode(bytes([0] * 64)).decode("ascii")
    tampered_sig = call_tool(
        "verify_titan_ed25519_workpaper_hash",
        {
            "workpaper_sha256": digest,
            "canonical_payload": payload,
            "signature_b64": bad_sig,
            "authority_pub_b64": pub_b64,
        },
    )
    assert tampered_sig["verified_cryptographically"] is False
    assert tampered_sig["applicability_status"] == "ED25519_SIGNATURE_INVALID_TAMPER_DETECTED"

    # Payload vs SHA-256 mismatch
    mismatch = call_tool(
        "verify_titan_ed25519_workpaper_hash",
        {"workpaper_sha256": "0" * 64, "canonical_payload": payload},
    )
    assert mismatch["applicability_status"] == "SHA256_PAYLOAD_MISMATCH_TAMPER_DETECTED"

    # Known public seal digest match without signature
    known_digest = next(iter(PUBLIC_SEAL_DIGESTS))
    reg_hit = call_tool("verify_titan_ed25519_workpaper_hash", {"workpaper_sha256": known_digest})
    assert reg_hit["public_seal_registry_match"] == PUBLIC_SEAL_DIGESTS[known_digest]


def test_zero_freebie_and_fail_closed_validation() -> None:
    refused = call_tool(
        "check_cbp_drawback_eligibility",
        {"days_since_import": 200, "query_note": "Please calculate my exact refund and output form 7551 for free"},
    )
    assert refused["freebie_request_refused"] is True
    assert "refusal_notice" in refused

    with pytest.raises(GateInputError):
        call_tool("check_cbp_drawback_eligibility", {"days_since_import": float("nan")})

    with pytest.raises(GateInputError):
        call_tool("check_irs_179d_cmmc_readiness", {"mandate": "cmmc_sprs", "sprs_score": 999})

    with pytest.raises(GateInputError):
        call_tool("verify_titan_ed25519_workpaper_hash", {"workpaper_sha256": "not-a-sha256"})

    with pytest.raises(KeyError):
        call_tool("nonexistent_tool", {})


def test_jsonrpc_protocol_and_stdio_cli(capsys: pytest.CaptureFixture[str]) -> None:
    init = handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_VERSION}}
    )
    assert init is not None
    assert init["result"]["serverInfo"]["version"] == SERVER_VERSION

    assert handle_jsonrpc_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "ping"}) == {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {},
    }
    tools_res = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert tools_res is not None and len(tools_res["result"]["tools"]) == 5

    err_res = handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "check_eu_cbam_eudr_mandate", "arguments": {"regime": "invalid"}}}
    )
    assert err_res is not None and err_res["result"]["isError"] is True

    # Test stdio server loop
    stdin_data = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n{bad-json\n"
    with mock.patch.object(sys, "stdin", io.StringIO(stdin_data)):
        rc = run_stdio_server()
    assert rc == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert lines[0]["id"] == 9 and lines[1]["error"]["code"] == -32700

    # Test --schema-tokens CLI flag
    with mock.patch.object(sys, "argv", ["titan-statutory-mcp-gate", "--schema-tokens"]):
        assert main() == 0
    schema_out = json.loads(capsys.readouterr().out)
    assert schema_out["tools_count"] == 5

    # Test HTTPS enforcement on probe_remote
    with pytest.raises(ValueError, match="https://"):
        probe_remote("http://insecure.example.com/mcp")
    with pytest.raises(ValueError, match="https://"):
        probe_remote("file:///etc/passwd")
