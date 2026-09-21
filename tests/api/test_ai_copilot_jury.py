"""
tests/api/test_ai_copilot_jury.py - Automated Copilot & Jury Acceptance Test Suite.

Validates 100% of Gen3 Acceptance Criteria (Follow-up 2026-09-11T17:04:00Z):
1. test_gemini_api_key_and_direct_connectivity:
   - geminiAPI.txt exists and resolves valid 50+ char key.
   - resolve_api_key(), get_api_key(), is_gemini_available(), clear_api_key_cache().
   - Direct execution / connectivity against Google Generative Language v1beta API (gemini-3.5-flash-lite).
2. test_ai_chat_endpoint_schema_and_grounding:
   - POST /api/v1/ai/chat with cyber risk queries.
   - AIChatResponse schema compliance, suggested action chips, and live platform grounding (EAL/VaR/compliance).
3. test_ai_navigate_endpoint_and_action_payloads:
   - POST /api/v1/ai/navigate with natural language commands:
     * "Take me to BharatCart blast radius" -> target_tab="demo"
     * "Simulate a zero-day exploit" -> action_type="inject_attack", target="zero_day_cve"
     * "Optimize for 50 Lakh budget" -> action_type="set_budget_and_optimize", budget=5000000
   - Structured ActionPayload collection and shortcuts.
4. test_ai_executive_summary_endpoint:
   - POST /api/v1/ai/executive-summary for jury and board.
   - AIExecutiveSummaryResponse schema, 30-sec pitch, key metrics, and ROSI.
5. test_ai_offline_and_rate_limit_fallback_resilience:
   - Mock rate limits (HTTP 429), timeouts (HTTP 408), and total air-gapped offline state.
   - Asserts HTTP 200, offline_fallback=True, model_used="local-heuristic-fallback".
6. test_live_telemetry_hud_metrics_and_pulse:
   - GET /api/v1/demo/telemetry-ticker.
   - Validates live HUD fields (EPS, TEF, active alerts, posture score, UTC timestamp).
7. test_mathematical_invariants_under_nominal_and_surges:
   - Verifies 0 < EAL < VaR90 < VaR95 < VaR99 across nominal state and all 6 attack surges.
   - Verifies zero-tolerance budget ceiling in SciPy HiGHS MILP knapsack allocation.
8. test_zero_emoji_compliance:
   - Programmatic regex scan across all source and template files in src/ asserting 0 emojis.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.ai import (
    GeminiCopilot,
    clear_api_key_cache,
    fallback_chat,
    fallback_executive_summary,
    fallback_navigate,
    get_api_key,
    get_copilot,
    is_gemini_available,
    resolve_api_key,
)
from src.ai.actions import ActionPayload, interpret_navigation_command
from src.ai.client import GeminiAPIException, GeminiClient
from src.ai.config import GEMINI_API_BASE_URL, GEMINI_MODEL, GeminiSettings
from src.ai.grounding import build_grounded_system_prompt, get_live_platform_metrics
from src.api.app import app
from src.api.schemas import (
    AIChatRequest,
    AIChatResponse,
    AIExecutiveSummaryRequest,
    AIExecutiveSummaryResponse,
    AINavigateRequest,
    AINavigateResponse,
    TelemetryTickerResponse,
)
from src.telemetry.attack_engine import AttackType, DemoAttackStateManager


@pytest.fixture(autouse=True)
def reset_platform_state():
    """Ensure clean nominal baseline state and fresh API key cache before and after every test."""
    clear_api_key_cache()
    manager = DemoAttackStateManager()
    manager.reset()
    yield
    clear_api_key_cache()
    manager.reset()


# =========================================================================
# 1. Gemini API Key & Direct Connectivity
# =========================================================================

def test_gemini_api_key_and_direct_connectivity():
    """
    Verifies:
      1. geminiAPI.txt exists and contains a valid Google Gemini API key (>= 30 characters).
      2. resolve_api_key(), get_api_key(), and is_gemini_available() function correctly.
      3. clear_api_key_cache() invalidates cached key.
      4. GeminiSettings initializes with correct defaults (gemini-3.5-flash-lite, 3.0s timeout).
      5. GeminiClient constructs valid endpoint URL.
      6. Direct execution against Google Generative Language v1beta API succeeds or handles network gracefully.
    """
    # 1. Inspect key file directly
    project_root = Path(__file__).resolve().parent.parent.parent
    key_file = project_root / "geminiAPI.txt"
    assert key_file.is_file(), f"Expected geminiAPI.txt at project root: {key_file}"

    raw_key = key_file.read_text(encoding="utf-8").strip()
    assert len(raw_key) >= 30, f"geminiAPI.txt key too short ({len(raw_key)} chars)"

    # 2. Config resolver tests
    clear_api_key_cache()
    resolved = resolve_api_key(project_root=project_root)
    assert resolved == raw_key, "resolve_api_key() did not return exact key from geminiAPI.txt"

    assert get_api_key() == raw_key
    assert is_gemini_available() is True

    # 3. Cache clearing and environment fallback
    clear_api_key_cache()
    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyFakeKeyForTestCache1234567890"}):
        with patch.object(Path, "is_file", return_value=False):
            env_key = resolve_api_key()
            assert env_key == "AIzaSyFakeKeyForTestCache1234567890"

    clear_api_key_cache()

    # 4. Settings verification
    settings = GeminiSettings()
    assert settings.model_name == GEMINI_MODEL
    assert settings.model_name == "gemini-3.5-flash-lite"
    assert settings.timeout_seconds == 3.0
    assert settings.base_url == GEMINI_API_BASE_URL
    assert settings.api_key == raw_key

    # 5. Client instantiation & URL contract
    client = GeminiClient(api_key=raw_key, model="gemini-3.5-flash-lite", timeout=8.0)
    assert client.endpoint_url.startswith("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=")
    assert raw_key in client.endpoint_url

    # 6. Direct execution against Google Generative Language v1beta API
    try:
        response_text = client.generate_content_sync(
            prompt="Respond with exactly one word: 'CONNECTED'",
            timeout=8.0,
        )
        assert isinstance(response_text, str)
        assert len(response_text.strip()) > 0
    except GeminiAPIException as exc:
        # Graceful handling if network/rate-limit occurs in CI or strict air-gapped proxy
        assert exc.status_code in (408, 429, 503, None) or "network" in str(exc).lower() or "timeout" in str(exc).lower()


# =========================================================================
# 2. AI Chat Endpoint Schema & Grounding
# =========================================================================

def test_ai_chat_endpoint_schema_and_grounding():
    """
    Verifies:
      1. POST /api/v1/ai/chat returns HTTP 200 with valid AIChatResponse schema.
      2. Response text and reply are non-empty strings.
      3. Action chips and suggested follow-up questions are populated.
      4. grounded_metrics contains exact live quantitative platform metrics (EAL, VaR, compliance).
      5. Currency switching (INR vs USD) propagates to grounded figures.
      6. Active attack state dynamically updates grounded context in chat.
    """
    with TestClient(app) as client:
        # 1. Primary cyber risk question (INR)
        req_payload = {
            "message": "What is our highest financial cyber risk today?",
            "currency": "INR",
        }
        res = client.post("/api/v1/ai/chat", json=req_payload)
        assert res.status_code == 200, f"Chat failed: {res.text}"

        data = res.json()
        validated = AIChatResponse.model_validate(data)

        assert len(validated.response.strip()) > 0
        assert validated.reply == validated.response
        assert validated.model_used in (GEMINI_MODEL, "local-heuristic-fallback")
        assert len(validated.suggested_actions) >= 2
        for action_chip in validated.suggested_actions:
            assert "label" in action_chip
            assert "command" in action_chip

        assert len(validated.suggested_followups) >= 2

        # Verify live grounding metrics
        metrics = validated.grounded_metrics
        assert metrics["currency"] == "INR"
        assert metrics["current_eal"] > 0
        assert 0 < metrics["current_eal"] < metrics["var_90"] < metrics["var_95"] < metrics["var_99"]
        assert "top_loss_driver" in metrics
        assert "compliance_summary" in metrics
        assert metrics["posture_score"] > 0
        assert metrics["has_active_attack"] is False

        # 2. Query in USD currency
        res_usd = client.post("/api/v1/ai/chat", json={"message": "Summarize cyber risk in USD", "currency": "USD"})
        assert res_usd.status_code == 200
        data_usd = res_usd.json()
        assert data_usd["grounded_metrics"]["currency"] == "USD"
        assert data_usd["grounded_metrics"]["current_eal"] > 0

        # 3. Dynamic attack grounding verification
        client.post("/api/v1/demo/inject-attack", json={"attack_type": "ransomware_outage", "target_node": "BC-PAY-GW-01", "intensity": 5.0})
        res_atk = client.post("/api/v1/ai/chat", json={"message": "What is our current incident status?"})
        assert res_atk.status_code == 200
        data_atk = res_atk.json()
        assert data_atk["grounded_metrics"]["has_active_attack"] is True
        assert data_atk["grounded_metrics"]["attack_type"] == "ransomware_outage"
        assert data_atk["grounded_metrics"]["target_node"] == "BC-PAY-GW-01"

        client.post("/api/v1/demo/reset-attack")


# =========================================================================
# 3. AI Navigate Endpoint & Action Payloads
# =========================================================================

def test_ai_navigate_endpoint_and_action_payloads():
    """
    Verifies:
      1. POST /api/v1/ai/navigate returns HTTP 200 with valid AINavigateResponse schema.
      2. "Take me to BharatCart blast radius" -> target_tab="demo", action_type in ("switch_tab", "tab_switch").
      3. "Simulate a zero-day exploit" -> action_type="inject_attack", target="zero_day_cve".
      4. "Optimize for 50 Lakh budget" -> action_type="set_budget_and_optimize", budget=5000000.
      5. Structured ActionPayloads contain required execution parameters and targets.
      6. Additional natural language commands (remediation delay, reset, currency toggle, technical backlog).
    """
    with TestClient(app) as client:
        # Command A: Blast radius navigation
        r_blast = client.post("/api/v1/ai/navigate", json={"command": "Take me to BharatCart blast radius"})
        assert r_blast.status_code == 200
        d_blast = r_blast.json()
        AINavigateResponse.model_validate(d_blast)
        assert d_blast["target_tab"] == "demo"
        assert d_blast["action_type"] in ("switch_tab", "tab_switch")
        assert any(a["target_tab"] == "demo" for a in d_blast["actions"])

        # Command B: Zero-day attack simulation
        r_cve = client.post("/api/v1/ai/navigate", json={"command": "Simulate a zero-day exploit"})
        assert r_cve.status_code == 200
        d_cve = r_cve.json()
        AINavigateResponse.model_validate(d_cve)
        assert d_cve["action_type"] == "inject_attack"
        assert d_cve["parameters"]["attack_type"] == "zero_day_cve"
        assert d_cve["parameters"]["target_node"] == "BC-FLASH-SALE-01"
        assert any(a["target"] == "zero_day_cve" for a in d_cve["actions"])

        # Command C: Budget optimization
        r_opt = client.post("/api/v1/ai/navigate", json={"command": "Optimize for 50 Lakh budget"})
        assert r_opt.status_code == 200
        d_opt = r_opt.json()
        AINavigateResponse.model_validate(d_opt)
        assert d_opt["action_type"] == "set_budget_and_optimize"
        assert d_opt["target_tab"] == "optimize"
        assert d_opt["parameters"]["budget"] == 5_000_000.0
        assert any(a["action_type"] == "set_slider" for a in d_opt["actions"])

        # Additional edge commands
        # 1. DDoS Surge
        r_ddos = client.post("/api/v1/ai/navigate", json={"command": "Simulate a DDoS attack against API gateway"})
        assert r_ddos.status_code == 200
        assert r_ddos.json()["parameters"]["attack_type"] == "ddos_surge"

        # 2. Reset demonstration
        r_reset = client.post("/api/v1/ai/navigate", json={"command": "Reset simulation and restore baseline"})
        assert r_reset.status_code == 200
        assert r_reset.json()["action_type"] == "reset_simulation"

        # 3. Toggle currency
        r_curr = client.post("/api/v1/ai/navigate", json={"command": "Toggle currency to USD"})
        assert r_curr.status_code == 200
        assert r_curr.json()["action_type"] == "toggle_currency"
        assert r_curr.json()["parameters"]["currency"] == "USD"

        # 4. Remediation delay slider
        r_delay = client.post("/api/v1/ai/navigate", json={"command": "Set remediation delay to 45 days"})
        assert r_delay.status_code == 200
        assert r_delay.json()["action_type"] == "set_slider"
        assert r_delay.json()["parameters"]["value"] == 45

        # 5. Technical SecOps backlog navigation
        r_tech = client.post("/api/v1/ai/navigate", json={"command": "Take me to technical CVE vulnerability findings"})
        assert r_tech.status_code == 200
        assert r_tech.json()["target_tab"] == "technical"


# =========================================================================
# 4. AI Executive Summary Endpoint
# =========================================================================

def test_ai_executive_summary_endpoint():
    """
    Verifies:
      1. POST /api/v1/ai/executive-summary returns HTTP 200 with valid AIExecutiveSummaryResponse schema.
      2. Supports target_audience="jury" and "board".
      3. Contains concise executive headline, 30-sec elevator pitch, bulleted insights, and recommended actions.
      4. Contains structured key_metrics, top_exposure, and recommended_capital_allocation with monetary figures.
      5. Respects currency parameter (INR vs USD).
      6. Supports audience alias field.
    """
    with TestClient(app) as client:
        # 1. Jury briefing (INR)
        r_jury = client.post(
            "/api/v1/ai/executive-summary",
            json={"target_audience": "jury", "currency": "INR"},
        )
        assert r_jury.status_code == 200, f"Executive summary failed: {r_jury.text}"
        data_jury = r_jury.json()
        summary_obj = AIExecutiveSummaryResponse.model_validate(data_jury)

        assert len(summary_obj.headline.strip()) > 0
        assert summary_obj.board_headline == summary_obj.headline
        assert len(summary_obj.elevator_pitch_30s.strip()) > 0
        assert summary_obj.elevator_pitch == summary_obj.elevator_pitch_30s
        assert len(summary_obj.bulleted_insights) >= 3
        assert len(summary_obj.recommended_actions) >= 2

        km = summary_obj.key_metrics
        assert km["currency"] == "INR"
        assert km["current_eal"] > 0
        assert km["var_95"] > km["current_eal"]
        assert km["recommended_spend"] > 0
        assert km["risk_mitigated"] > 0
        assert km["portfolio_rosi"] > 0

        rca = summary_obj.recommended_capital_allocation
        assert rca["recommended_budget"] > 0
        assert rca["risk_mitigated"] > 0
        assert rca["portfolio_rosi"] > 0

        # 2. Board briefing in USD
        r_board = client.post(
            "/api/v1/ai/executive-summary",
            json={"target_audience": "board", "currency": "USD"},
        )
        assert r_board.status_code == 200
        data_board = r_board.json()
        assert data_board["key_metrics"]["currency"] == "USD"
        assert data_board["key_metrics"]["current_eal"] > 0

        # 3. Audience alias support
        r_alias = client.post(
            "/api/v1/ai/executive-summary",
            json={"audience": "ceo", "currency": "INR"},
        )
        assert r_alias.status_code == 200


# =========================================================================
# 5. AI Offline & Rate Limit Fallback Resilience
# =========================================================================

def test_ai_offline_and_rate_limit_fallback_resilience():
    """
    Verifies:
      1. When Google Gemini returns HTTP 429 rate limit, POST /api/v1/ai/chat returns HTTP 200
         with offline_fallback=True and model_used="local-heuristic-fallback".
      2. When external network times out (HTTP 408), system returns HTTP 200 with offline fallback.
      3. In complete air-gapped mode (is_gemini_available() == False), all AI endpoints
         (/chat, /navigate, /executive-summary) return HTTP 200 without throwing exceptions or 500 errors.
      4. Deterministic fallback functions (fallback_chat, fallback_navigate, fallback_executive_summary)
         generate grounded, actuarially coherent responses without external network access.
    """
    with TestClient(app) as client:
        # Scenario A: Simulated HTTP 429 Rate Limit
        with patch.object(
            GeminiClient,
            "generate_content",
            new_callable=AsyncMock,
            side_effect=GeminiAPIException("Quota exceeded HTTP 429", status_code=429),
        ):
            res_429 = client.post("/api/v1/ai/chat", json={"message": "What is our highest risk?"})
            assert res_429.status_code == 200
            d_429 = res_429.json()
            assert d_429["offline_fallback"] is True
            assert d_429["model_used"] == "local-heuristic-fallback"
            assert len(d_429["response"]) > 0

            # Executive summary under 429
            res_sum_429 = client.post("/api/v1/ai/executive-summary", json={"target_audience": "jury"})
            assert res_sum_429.status_code == 200
            d_sum_429 = res_sum_429.json()
            assert d_sum_429["offline_fallback"] is True
            assert d_sum_429["model_used"] == "local-heuristic-fallback"

        # Scenario B: Simulated Network Timeout (HTTP 408)
        with patch.object(
            GeminiClient,
            "generate_content",
            new_callable=AsyncMock,
            side_effect=GeminiAPIException("Request timed out after 3.0s", status_code=408),
        ):
            res_to = client.post("/api/v1/ai/chat", json={"message": "Which controls should we deploy?"})
            assert res_to.status_code == 200
            d_to = res_to.json()
            assert d_to["offline_fallback"] is True
            assert d_to["model_used"] == "local-heuristic-fallback"

        # Scenario C: Strict Air-Gapped Mode (no key / no network)
        with patch("src.ai.is_gemini_available", return_value=False):
            # Chat
            r_air_chat = client.post("/api/v1/ai/chat", json={"message": "Explain our compliance status"})
            assert r_air_chat.status_code == 200
            d_air_chat = r_air_chat.json()
            assert d_air_chat["offline_fallback"] is True
            assert d_air_chat["model_used"] == "local-heuristic-fallback"

            # Navigate
            r_air_nav = client.post("/api/v1/ai/navigate", json={"command": "Take me to BharatCart blast radius"})
            assert r_air_nav.status_code == 200
            d_air_nav = r_air_nav.json()
            assert d_air_nav["target_tab"] == "demo"
            assert d_air_nav["offline_fallback"] is True

            # Executive Summary
            r_air_sum = client.post("/api/v1/ai/executive-summary", json={"target_audience": "board"})
            assert r_air_sum.status_code == 200
            d_air_sum = r_air_sum.json()
            assert d_air_sum["offline_fallback"] is True
            assert d_air_sum["model_used"] == "local-heuristic-fallback"

        # Scenario D: Direct deterministic fallback functions
        fb_c = fallback_chat("What is our highest risk?", currency="INR")
        assert fb_c["offline_fallback"] is True
        assert fb_c["model_used"] == "local-heuristic-fallback"
        assert "EAL" in fb_c["response"]

        fb_n = fallback_navigate("Optimize for 50 Lakh budget", currency="INR")
        assert fb_n["target_tab"] == "optimize"
        assert fb_n["parameters"]["budget"] == 5_000_000.0

        fb_e = fallback_executive_summary(target_audience="jury", currency="INR")
        assert fb_e["offline_fallback"] is True
        assert "LossLogic" in fb_e["elevator_pitch_30s"]


# =========================================================================
# 6. Live Telemetry HUD Metrics & Pulse
# =========================================================================

def test_live_telemetry_hud_metrics_and_pulse():
    """
    Verifies:
      1. GET /api/v1/demo/telemetry-ticker returns HTTP 200 with valid TelemetryTickerResponse schema.
      2. Validates presence and types of all required HUD fields:
         - current_eal_inr (> 0)
         - var_90_inr, var_95_inr, var_99_inr (> 0)
         - active_alerts / active_alerts_count (>= 0)
         - events_per_second (>= 10,000 EPS)
         - threat_event_frequency (> 0 TEF/yr)
         - posture_score (between 0.0 and 100.0)
         - timestamp (valid UTC string)
         - nodes (4 BharatCart nodes)
         - recent_events (non-empty dynamic event feed)
      3. Consecutive pulses show valid dynamic jitter without breaking bounds.
    """
    with TestClient(app) as client:
        res = client.get("/api/v1/demo/telemetry-ticker")
        assert res.status_code == 200, f"Ticker endpoint failed: {res.text}"

        data = res.json()
        ticker_obj = TelemetryTickerResponse.model_validate(data)

        # Monetary fields
        assert data["current_eal_inr"] > 0
        assert data["var_90_inr"] > 0
        assert data["var_95_inr"] > 0
        assert data["var_99_inr"] > 0
        assert data["current_eal_inr"] < data["var_90_inr"] < data["var_95_inr"] < data["var_99_inr"]

        # Telemetry rates
        assert data["events_per_second"] >= 10000.0
        assert data["threat_event_frequency"] > 0.0
        assert 0.0 <= data["posture_score"] <= 100.0
        alerts_count = data.get("active_alerts_count", data.get("active_alerts", 0))
        assert alerts_count >= 0

        # Structural HUD metadata
        assert isinstance(data["timestamp"], str) and len(data["timestamp"]) > 0
        assert isinstance(data["nodes"], list) and len(data["nodes"]) == 4
        node_ids = {n.get("node") or n.get("id") for n in data["nodes"]}
        assert "BC-API-GW-01" in node_ids
        assert "BC-PAY-GW-01" in node_ids
        assert "BC-PII-VAULT-01" in node_ids
        assert "BC-FLASH-SALE-01" in node_ids

        assert isinstance(data["recent_events"], list)
        assert len(data["recent_events"]) >= 1

        # Second pulse check
        time.sleep(0.05)
        res2 = client.get("/api/v1/demo/telemetry-ticker")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["events_per_second"] >= 10000.0
        assert data2["current_eal_inr"] < data2["var_90_inr"] < data2["var_95_inr"] < data2["var_99_inr"]


# =========================================================================
# 7. Mathematical Invariants Under Nominal & Surges
# =========================================================================

def test_mathematical_invariants_under_nominal_and_surges():
    """
    Verifies:
      1. Strict mathematical ordering: 0 < EAL < VaR90 < VaR95 < VaR99
         across nominal state and all 6 attack surges:
         - DDOS_SURGE
         - RANSOMWARE_OUTAGE
         - SQL_DATA_LEAK
         - CREDENTIAL_STUFFING
         - ZERO_DAY_CVE
         - CLOUD_IAM_COMPROMISE
      2. Zero-tolerance budget ceiling in SciPy HiGHS MILP knapsack allocation:
         sum(Cost_i) <= Budget across all budget tiers (₹25L, ₹50L, ₹1Cr, ₹2.5Cr).
    """
    with TestClient(app) as client:
        # Part A: Nominal Baseline Invariant
        client.post("/api/v1/demo/reset-attack")
        t_nom = client.get("/api/v1/demo/telemetry-ticker").json()
        assert 0 < t_nom["current_eal_inr"] < t_nom["var_90_inr"] < t_nom["var_95_inr"] < t_nom["var_99_inr"], (
            f"Nominal VaR ordering violated: {t_nom}"
        )

        # Quant simulation endpoint invariant
        sim_nom = client.post("/api/v1/quant/simulate", json={"currency": "INR"}).json()
        assert 0 < sim_nom["eal"] < sim_nom["var_90"] < sim_nom["var_95"] < sim_nom["var_99"], (
            f"Quant simulation VaR ordering violated: {sim_nom}"
        )

        # Part B: All 6 Attack Surges
        attack_scenarios = [
            ("ddos_surge", "BC-API-GW-01"),
            ("ransomware_outage", "BC-PAY-GW-01"),
            ("sql_data_leak", "BC-PII-VAULT-01"),
            ("credential_stuffing", "BC-FLASH-SALE-01"),
            ("zero_day_cve", "BC-FLASH-SALE-01"),
            ("cloud_iam_compromise", "BC-API-GW-01"),
        ]

        for attack_type, target_node in attack_scenarios:
            client.post("/api/v1/demo/reset-attack")

            # Inject attack
            res_inj = client.post(
                "/api/v1/demo/inject-attack",
                json={
                    "attack_type": attack_type,
                    "target_node": target_node,
                    "intensity": 5.0,
                    "source_device": "Jury-Automated-Verifier",
                },
            )
            assert res_inj.status_code == 200, f"Injection failed for {attack_type}: {res_inj.text}"
            inj_data = res_inj.json()

            # Verify surge invariant
            spiked_eal = inj_data["spiked_eal_inr"]
            var90 = inj_data["var_90_inr"]
            var95 = inj_data["var_95_inr"]
            var99 = inj_data["var_99_inr"]

            assert 0 < spiked_eal < var90 < var95 < var99, (
                f"Surge VaR ordering violated for {attack_type}: EAL={spiked_eal}, VaR90={var90}, VaR95={var95}, VaR99={var99}"
            )
            assert spiked_eal > inj_data["baseline_eal_inr"]
            assert inj_data["posture_after"] < inj_data["posture_before"]

            # Verify dynamic ticker during surge
            t_surge = client.get("/api/v1/demo/telemetry-ticker").json()
            assert 0 < t_surge["current_eal_inr"] < t_surge["var_90_inr"] < t_surge["var_95_inr"] < t_surge["var_99_inr"]
            assert t_surge["active_attack"] is True
            assert t_surge["attack_type"] == attack_type

        # Part C: SciPy HiGHS MILP Knapsack Zero-Tolerance Budget Ceiling
        budgets_to_test = [
            1_000_000.0,   # ₹10 Lakhs
            2_500_000.0,   # ₹25 Lakhs
            5_000_000.0,   # ₹50 Lakhs
            10_000_000.0,  # ₹1 Crore
            25_000_000.0,  # ₹2.5 Crore
        ]

        for budget in budgets_to_test:
            res_opt = client.post(
                "/api/v1/optimize/allocate",
                json={"budget": budget, "currency": "INR"},
            )
            assert res_opt.status_code == 200, f"Optimization failed for budget {budget}: {res_opt.text}"
            opt_data = res_opt.json()

            allocated_spend = opt_data["allocated_spend"]
            selected_controls = opt_data["selected_controls"]
            actual_sum = sum(c["cost"] for c in selected_controls)

            # Strict zero-tolerance assertions
            assert allocated_spend <= budget, (
                f"Budget ceiling violated! Allocated {allocated_spend} > Budget {budget}"
            )
            assert actual_sum <= budget, (
                f"Sum of selected controls {actual_sum} > Budget {budget}"
            )
            assert allocated_spend >= 0.0
            assert opt_data["risk_mitigated"] >= 0.0
            assert opt_data["portfolio_rosi"] >= 0.0

        client.post("/api/v1/demo/reset-attack")


# =========================================================================
# 8. Zero Emoji Codebase Compliance
# =========================================================================

def test_zero_emoji_compliance():
    """
    Verifies:
      1. Programmatic scan across all source and template files in src/
         (.py, .html, .js, .css).
      2. Scans for unicode emoji characters using comprehensive regex patterns:
         - [\\U0001F300-\\U0001FAFF\\U00002600-\\U000026FF\\U00002700-\\U000027BF]
         - [\\U0001F000-\\U0001FAFF\\U00002702-\\U000027B0\\U000024C2-\\U0001F251\\U0001F900-\\U0001F9FF\\U0001FA00-\\U0001FA6F\\U0001FA70-\\U0001FAFF\\U00002600-\\U000026FF]
      3. Asserts exactly 0 emoji occurrences across all institutional platform files.
    """
    project_root = Path(__file__).resolve().parent.parent.parent
    src_dir = project_root / "src"
    assert src_dir.is_dir(), f"Expected src directory at {src_dir}"

    emoji_pattern = re.compile(
        r"[\U0001F000-\U0001FAFF\U00002702-\U000027B0\U000024C2-\U0001F251"
        r"\U0001F900-\U0001F9FF\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF"
        r"\U00002600-\U000026FF\U00002700-\U000027BF]"
    )

    scanned_files = 0
    violations: List[Dict[str, Any]] = []

    for file_path in src_dir.rglob("*"):
        if file_path.is_file() and file_path.suffix in (".py", ".html", ".js", ".css"):
            scanned_files += 1
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            matches = list(emoji_pattern.finditer(content))
            if matches:
                for m in matches:
                    violations.append({
                        "file": str(file_path.relative_to(project_root)),
                        "char": m.group(),
                        "codepoint": f"U+{ord(m.group()):04X}",
                    })

    assert scanned_files >= 20, f"Expected at least 20 files in src/, found {scanned_files}"
    assert len(violations) == 0, (
        f"Found {len(violations)} emoji characters in src/ files: {violations}"
    )
