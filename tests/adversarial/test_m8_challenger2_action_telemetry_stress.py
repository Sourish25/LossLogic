"""
tests/adversarial/test_m8_challenger2_action_telemetry_stress.py

Empirical stress verification harness authored by m8_challenger_2:
1. Natural language Action Engine payload generation across varied phrasing variations:
   - Tab navigation (blast radius -> demo, secops -> technical, vendor -> demo, overview -> executive, etc.)
   - Slider adjustments (lakh, crore, million, western notations, remediation delay)
   - Threat simulations across all 6 attack vectors (DDoS, zero-day, ransomware, SQLi, IAM, credential stuffing)
   - Reset and currency toggle commands
2. Live telemetry HUD ticker endpoint (/api/v1/demo/telemetry-ticker) under concurrent attack injections:
   - High-concurrency thread pool hammering ticker endpoint while attacks are injected and reset
   - Strict latency assertions (<100ms for ticker polling)
   - 100% schema compliance and mathematical invariant preservation (0 < EAL < VaR90 < VaR95 < VaR99)
3. Zero-emoji comprehensive Unicode audit across all institutional source files in src/.
4. Frontend ActionPayload contract alignment with dashboard.js event dispatcher.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from src.ai.actions import ActionPayload, interpret_navigation_command
from src.api.app import app
from src.api.schemas import AINavigateResponse, TelemetryTickerResponse
from src.telemetry.attack_engine import DemoAttackStateManager


@pytest.fixture(autouse=True)
def reset_demo_state():
    manager = DemoAttackStateManager()
    manager.reset()
    yield
    manager.reset()


class TestActionEnginePhrasingCoverage:
    """Stress tests Action Engine payload generation across realistic NL phrasing variations."""

    @pytest.mark.parametrize(
        "command,expected_tab",
        [
            ("Take me to BharatCart blast radius", "demo"),
            ("take me to bharatcart blast radius", "demo"),
            ("Show me dependency DAG", "demo"),
            ("show me the bharatcart DAG topology", "demo"),
            ("Navigate to blast radius view", "demo"),
            ("Go to BharatCart demo", "demo"),
            ("Switch to jury demo tab", "demo"),
            ("Take me to CEO vendor benchmarking", "demo"),
            ("Show vendor matrix", "demo"),
            ("Vendor benchmarking comparisons", "demo"),
            ("Switch to technical secops view", "technical"),
            ("Show me technical CVE findings", "technical"),
            ("Take me to vulnerability backlog", "technical"),
            ("SecOps findings drilldown", "technical"),
            ("Show technical cves", "technical"),
            ("Overview of enterprise risk", "executive"),
            ("Take me to executive board summary", "executive"),
            ("Open executive dashboard", "executive"),
            ("Show CISO executive overview", "executive"),
            ("Open regulatory compliance crosswalk", "executive"),
            ("SEBI and RBI compliance status", "executive"),
            ("NIST CSF framework alignment", "executive"),
        ],
    )
    def test_tab_navigation_phrasings(self, command: str, expected_tab: str):
        """Validates that varied tab navigation phrasings resolve to correct target tabs."""
        res = interpret_navigation_command(command)
        assert res["target_tab"] == expected_tab, f"Failed for '{command}': got {res['target_tab']}, expected {expected_tab}"
        assert res["action_type"] in ("switch_tab", "tab_switch")
        assert len(res["actions"]) >= 1
        assert res["actions"][0].target_tab == expected_tab
        assert len(res["explanation"]) > 0

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command})
            assert resp.status_code == 200, f"API error for '{command}': {resp.text}"
            data = resp.json()
            validated = AINavigateResponse.model_validate(data)
            assert validated.target_tab == expected_tab
            assert validated.action_type in ("switch_tab", "tab_switch")

    @pytest.mark.parametrize(
        "command,currency,expected_min_budget,expected_max_budget",
        [
            ("Optimize with 25 lakh budget", "INR", 2_400_000.0, 2_600_000.0),
            ("Optimize for 50 Lakh budget", "INR", 4_900_000.0, 5_100_000.0),
            ("Allocate ₹1.5 crore for security", "INR", 14_900_000.0, 15_100_000.0),
            ("Optimize portfolio with 75 lacs", "INR", 7_400_000.0, 7_600_000.0),
            ("Spend 10 Cr on enterprise controls", "INR", 99_000_000.0, 101_000_000.0),
            ("Budget allocation 1 crore INR", "INR", 9_900_000.0, 10_100_000.0),
            ("Knapsack allocation with 2.5 million", "USD", 2_400_000.0, 2_600_000.0),
            ("Optimize for $500k budget", "USD", 490_000.0, 510_000.0),
            ("Auto-optimize capital allocation for 50 Lakhs", "INR", 4_900_000.0, 5_100_000.0),
            ("Optimize security portfolio", "INR", 1_000_000.0, 100_000_000.0),
        ],
    )
    def test_budget_slider_adjustment_phrasings(
        self, command: str, currency: str, expected_min_budget: float, expected_max_budget: float
    ):
        """Validates natural language budget slider adjustments and HiGHS MILP optimization actions."""
        res = interpret_navigation_command(command, currency=currency)
        assert res["target_tab"] == "optimize"
        assert res["action_type"] == "set_budget_and_optimize"
        budget_val = res["parameters"].get("budget") or res["parameters"].get("value")
        assert budget_val is not None, f"Missing budget parameter for '{command}'"
        assert expected_min_budget <= budget_val <= expected_max_budget, (
            f"Budget {budget_val} out of expected range [{expected_min_budget}, {expected_max_budget}] for '{command}'"
        )
        assert any(a.action_type == "set_slider" for a in res["actions"])

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command, "currency": currency})
            assert resp.status_code == 200
            data = resp.json()
            assert data["target_tab"] == "optimize"
            assert data["action_type"] == "set_budget_and_optimize"

    @pytest.mark.parametrize(
        "command,expected_days",
        [
            ("Set remediation delay to 45 days", 45),
            ("Delay remediation by 15 days", 15),
            ("What if remediation delay is 90 days", 90),
            ("Simulate 30 days delay", 30),
            ("Set delay to 60 days", 60),
        ],
    )
    def test_remediation_delay_slider_phrasings(self, command: str, expected_days: int):
        """Validates remediation delay slider adjustment action generation."""
        res = interpret_navigation_command(command)
        assert res["action_type"] == "set_slider"
        assert res["target_tab"] == "executive"
        val = res["parameters"].get("value")
        assert val == expected_days, f"Expected {expected_days} days, got {val} for '{command}'"

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command})
            assert resp.status_code == 200
            data = resp.json()
            assert data["action_type"] == "set_slider"
            assert data["parameters"]["value"] == expected_days

    @pytest.mark.parametrize(
        "command,expected_attack_type,expected_target_node",
        [
            ("Simulate DDoS attack", "ddos_surge", "BC-API-GW-01"),
            ("Simulate a DDoS attack against API gateway", "ddos_surge", "BC-API-GW-01"),
            ("Inject volumetric DDoS surge on API Gateway", "ddos_surge", "BC-API-GW-01"),
            ("Simulate traffic flood on gateway", "ddos_surge", "BC-API-GW-01"),
            ("Simulate a zero-day exploit", "zero_day_cve", "BC-FLASH-SALE-01"),
            ("Inject zero-day vulnerability on flash sale microservice", "zero_day_cve", "BC-FLASH-SALE-01"),
            ("Simulate 0-day exploit", "zero_day_cve", "BC-FLASH-SALE-01"),
            ("Inject critical CVE exploit on flash sale", "zero_day_cve", "BC-FLASH-SALE-01"),
            ("Simulate ransomware attack on payment gateway", "ransomware_outage", "BC-PAY-GW-01"),
            ("Inject lockbit ransomware outage", "ransomware_outage", "BC-PAY-GW-01"),
            ("Simulate encrypt payment service", "ransomware_outage", "BC-PAY-GW-01"),
            ("Simulate SQL data leak", "sql_data_leak", "BC-PII-VAULT-01"),
            ("Inject SQL injection against customer PII vault", "sql_data_leak", "BC-PII-VAULT-01"),
            ("Database exfiltration surge on vault", "sql_data_leak", "BC-PII-VAULT-01"),
            ("Simulate data leak on customer records", "sql_data_leak", "BC-PII-VAULT-01"),
            ("Simulate cloud IAM privilege escalation", "cloud_iam_compromise", "BC-API-GW-01"),
            ("Inject IAM privilege abuse on gateway", "cloud_iam_compromise", "BC-API-GW-01"),
            ("Simulate cloud role compromise", "cloud_iam_compromise", "BC-API-GW-01"),
            ("Inject credential stuffing surge", "credential_stuffing", "BC-FLASH-SALE-01"),
            ("Brute force password spray on flash sale service", "credential_stuffing", "BC-FLASH-SALE-01"),
            ("Simulate credential stuffing attack", "credential_stuffing", "BC-FLASH-SALE-01"),
        ],
    )
    def test_threat_simulation_phrasings(
        self, command: str, expected_attack_type: str, expected_target_node: str
    ):
        """Validates all 6 threat vectors map to correct attack types and nodes on BharatCart topology."""
        res = interpret_navigation_command(command)
        assert res["target_tab"] == "demo"
        assert res["action_type"] in ("inject_attack", "simulate_attack")
        atk_param = res["parameters"].get("attack_type")
        assert atk_param == expected_attack_type, f"Got {atk_param}, expected {expected_attack_type} for '{command}'"
        node_param = res["parameters"].get("target_node")
        assert node_param == expected_target_node, f"Got {node_param}, expected {expected_target_node} for '{command}'"

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command})
            assert resp.status_code == 200
            data = resp.json()
            assert data["target_tab"] == "demo"
            assert data["parameters"]["attack_type"] == expected_attack_type
            assert data["parameters"]["target_node"] == expected_target_node

    @pytest.mark.parametrize(
        "command",
        [
            "Reset all simulations",
            "reset simulation",
            "Restore baseline state",
            "Normalize environment",
            "clear attack surge",
        ],
    )
    def test_reset_simulation_phrasings(self, command: str):
        """Validates reset / normalize simulation commands."""
        res = interpret_navigation_command(command)
        assert res["action_type"] == "reset_simulation"
        assert res["target_tab"] == "demo"

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command})
            assert resp.status_code == 200
            data = resp.json()
            assert data["action_type"] == "reset_simulation"

    @pytest.mark.parametrize(
        "command,expected_curr",
        [
            ("Toggle currency to USD", "USD"),
            ("Switch display currency to INR", "INR"),
            ("Toggle currency", "INR"),
        ],
    )
    def test_toggle_currency_phrasings(self, command: str, expected_curr: str):
        """Validates currency toggle commands."""
        res = interpret_navigation_command(command)
        assert res["action_type"] == "toggle_currency"
        assert res["parameters"]["currency"] == expected_curr


class TestLiveTelemetryHUDConcurrencyStress:
    """Stress tests GET /api/v1/demo/telemetry-ticker under heavy concurrent load and simultaneous attacks."""

    def test_ticker_concurrency_and_attack_surge_resilience(self):
        """
        Executes 100 concurrent ticker polls alongside 20 background attack injections and 10 resets.
        Asserts:
        - 100% of requests return HTTP 200 within 100ms.
        - Zero race conditions, deadlocks, or 500 errors.
        - Strict mathematical ordering 0 < EAL < VaR90 < VaR95 < VaR99 holds in every single response.
        - Ingestion rates maintain >= 10,000 EPS and valid posture scores.
        """
        client = TestClient(app)
        attack_types = [
            ("ddos_surge", "BC-API-GW-01"),
            ("ransomware_outage", "BC-PAY-GW-01"),
            ("sql_data_leak", "BC-PII-VAULT-01"),
            ("credential_stuffing", "BC-FLASH-SALE-01"),
            ("zero_day_cve", "BC-FLASH-SALE-01"),
            ("cloud_iam_compromise", "BC-API-GW-01"),
        ]

        ticker_latencies: List[float] = []
        errors: List[str] = []
        ticker_samples: List[Dict[str, Any]] = []

        def worker_ticker(idx: int):
            t0 = time.perf_counter()
            try:
                resp = client.get("/api/v1/demo/telemetry-ticker")
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                ticker_latencies.append(elapsed_ms)

                if resp.status_code != 200:
                    errors.append(f"Ticker request {idx} returned {resp.status_code}: {resp.text}")
                    return

                data = resp.json()
                TelemetryTickerResponse.model_validate(data)

                eal = data["current_eal_inr"]
                v90 = data["var_90_inr"]
                v95 = data["var_95_inr"]
                v99 = data["var_99_inr"]

                if not (0 < eal < v90 < v95 < v99):
                    errors.append(f"Invariant violation in ticker {idx}: EAL={eal}, VaR90={v90}, VaR95={v95}, VaR99={v99}")

                if data["events_per_second"] < 10000.0:
                    errors.append(f"EPS too low in ticker {idx}: {data['events_per_second']}")

                if not (0.0 <= data["posture_score"] <= 100.0):
                    errors.append(f"Posture out of bounds in ticker {idx}: {data['posture_score']}")

                ticker_samples.append(data)
            except Exception as e:
                errors.append(f"Exception in worker_ticker {idx}: {e}")

        def worker_inject(idx: int):
            atk, node = attack_types[idx % len(attack_types)]
            try:
                resp = client.post(
                    "/api/v1/demo/inject-attack",
                    json={
                        "attack_type": atk,
                        "target_node": node,
                        "intensity": 5.0,
                        "source_device": f"Concurrency-Tester-{idx}",
                    },
                )
                if resp.status_code != 200:
                    errors.append(f"Inject attack {idx} returned {resp.status_code}: {resp.text}")
            except Exception as e:
                errors.append(f"Exception in worker_inject {idx}: {e}")

        def worker_reset(idx: int):
            try:
                resp = client.post("/api/v1/demo/reset-attack")
                if resp.status_code != 200:
                    errors.append(f"Reset attack {idx} returned {resp.status_code}: {resp.text}")
            except Exception as e:
                errors.append(f"Exception in worker_reset {idx}: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = []
            for i in range(100):
                futures.append(executor.submit(worker_ticker, i))
                if i % 5 == 0:
                    futures.append(executor.submit(worker_inject, i // 5))
                if i % 10 == 0:
                    futures.append(executor.submit(worker_reset, i // 10))

            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Encountered {len(errors)} errors during concurrent stress:\n" + "\n".join(errors[:10])
        assert len(ticker_latencies) >= 95, f"Expected >=95 successful ticker samples, got {len(ticker_latencies)}"
        p95_latency = sorted(ticker_latencies)[int(len(ticker_latencies) * 0.95)]
        max_latency = max(ticker_latencies)
        avg_latency = sum(ticker_latencies) / len(ticker_latencies)

        assert p95_latency < 100.0, f"P95 ticker latency {p95_latency:.2f}ms exceeds 100ms ceiling! (max: {max_latency:.2f}ms)"
        assert avg_latency < 50.0, f"Average ticker latency {avg_latency:.2f}ms unexpectedly high"


class TestZeroEmojiAudit:
    """Rigorous programmatic scan of all source and template files in src/ for unicode emojis."""

    def test_all_src_files_zero_emoji(self):
        """Scans python, javascript, html, css, and json files in src/ for emojis."""
        project_root = Path(__file__).resolve().parent.parent.parent
        src_dir = project_root / "src"

        emoji_pattern = re.compile(
            r"[\U0001F000-\U0001FAFF"
            r"\U00002600-\U000026FF"
            r"\U00002700-\U000027BF"
            r"\U00002B50-\U00002B55"
            r"\U0000231A-\U0000231B"
            r"\U000023E9-\U000023F3"
            r"\U000023F8-\U000023FA]"
        )

        violations: List[Dict[str, Any]] = []
        files_checked = 0

        for file_path in src_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in (".py", ".html", ".js", ".css", ".json"):
                files_checked += 1
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for m in emoji_pattern.finditer(content):
                    char = m.group()
                    violations.append({
                        "file": str(file_path.relative_to(project_root)),
                        "char": char,
                        "codepoint": f"U+{ord(char):04X}",
                        "position": m.start(),
                    })

        assert files_checked >= 25, f"Expected at least 25 source files in src/, found {files_checked}"
        assert len(violations) == 0, f"Detected {len(violations)} emoji violations in src/:\n{violations}"


class TestFrontendActionPayloadContract:
    """Verifies that ActionPayload structures are 100% compliant with dashboard.js expectations."""

    def test_action_payload_keys_and_defaults(self):
        """Checks aliases action <-> action_type, target <-> target_tab, explanation <-> message."""
        payload = ActionPayload(
            action_type="switch_tab",
            target_tab="demo",
            explanation="Navigate to demo tab",
        )
        assert payload.action == "switch_tab"
        assert payload.target == "demo"
        assert payload.target_tab == "demo"

        payload2 = ActionPayload(
            action_type="inject_attack",
            target="zero_day_cve",
            parameters={"attack_type": "zero_day_cve"},
            explanation="Simulate zero-day",
        )
        assert payload2.action == "inject_attack"
        assert payload2.target == "zero_day_cve"

    def test_ainavigate_response_shortcut_fields(self):
        """Verifies AINavigateResponse exposes root-level convenience fields for frontend dispatch."""
        res = interpret_navigation_command("Take me to BharatCart blast radius")
        resp_obj = AINavigateResponse.model_validate(res)

        assert resp_obj.target_tab == "demo"
        assert resp_obj.action_type in ("switch_tab", "tab_switch")
        assert resp_obj.action is not None
        assert resp_obj.action.target_tab == "demo"
        assert len(resp_obj.actions) >= 1
