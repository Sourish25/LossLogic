"""
tests/adversarial/test_challenger2_api_stress_empirical.py

Empirical stress verification harness authored by challenger_sih26_2:
1. API contract verification for /api/v1/ai/executive-summary across audience variations and empty body.
2. Natural language action navigation verification for /api/v1/ai/navigate across technical and executive intents.
3. Attack injection verification for /api/v1/demo/inject-attack across all 6 attack types with modern device names.
4. Dynamic telemetry ticker verification for /api/v1/demo/telemetry-ticker validating stochastic jitter and bounds.
5. Terminology grep verification across src/ and run_server.py asserting 0 occurrences of 'jury'.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.schemas import (
    AIExecutiveSummaryResponse,
    AINavigateResponse,
    AttackInjectionResponse,
    TelemetryTickerResponse,
    ResetAttackResponse,
)
from src.telemetry.attack_engine import AttackType, DemoAttackStateManager


@pytest.fixture(autouse=True)
def reset_state_fixture():
    """Ensure clean demonstration state before and after each test."""
    manager = DemoAttackStateManager()
    manager.reset()
    yield
    manager.reset()


class TestChallenger2ExecutiveSummaryContract:
    """Empirically tests POST /api/v1/ai/executive-summary contracts and backwards compatibility."""

    @pytest.mark.parametrize(
        "payload",
        [
            {"target_audience": "executive"},
            {"target_audience": "jury"},  # backwards compatibility maps to executive
            {"target_audience": "board"},
            {"target_audience": "ciso"},
            {},  # empty payload defaults to executive
        ],
    )
    def test_executive_summary_audience_matrix(self, payload: Dict[str, Any]):
        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/executive-summary", json=payload)
            assert resp.status_code == 200, f"Failed for payload {payload}: {resp.text}"
            data = resp.json()

            # Pydantic schema validation
            validated = AIExecutiveSummaryResponse.model_validate(data)
            assert validated.headline, "Headline must not be empty"
            assert validated.elevator_pitch_30s, "30-second elevator pitch must not be empty"
            assert len(validated.bulleted_insights) >= 3, "Bulleted insights must contain items"
            assert len(validated.recommended_actions) >= 1, "Recommended actions must contain items"
            assert validated.posture_assessment, "Posture assessment must not be empty"
            assert "current_eal" in validated.key_metrics, "Live metrics must include current_eal"

            # Check aliases
            assert validated.board_headline == validated.headline
            assert validated.summary_30s == validated.elevator_pitch_30s

            # Verify no jury terminology leaked into summary output
            full_text = f"{validated.headline} {validated.elevator_pitch_30s} {' '.join(validated.bulleted_insights)}"
            assert "jury" not in full_text.lower(), f"Unexpected 'jury' found in output for {payload}"

    def test_executive_summary_empty_body(self):
        """Specifically verifies that sending an empty JSON body {} defaults to executive audience."""
        from src.api.schemas import AIExecutiveSummaryRequest
        req = AIExecutiveSummaryRequest.model_validate({})
        assert req.target_audience == "executive"

        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/executive-summary", json={})
            assert resp.status_code == 200
            data = resp.json()
            validated = AIExecutiveSummaryResponse.model_validate(data)
            assert validated.headline
            assert validated.elevator_pitch_30s
            assert "jury" not in str(data).lower()



class TestChallenger2AINavigateContract:
    """Empirically tests POST /api/v1/ai/navigate routing contracts."""

    @pytest.mark.parametrize(
        "command,expected_tab",
        [
            ("Take me to BharatCart blast radius", "technical"),
            ("Show me dependency DAG", "technical"),
            ("Take me to CEO vendor benchmarking", "executive"),
            ("Show vendor matrix", "executive"),
            # Additional phrasing stress cases
            ("take me to bharatcart blast radius", "technical"),
            ("show me the bharatcart DAG topology", "technical"),
            ("Switch to technical secops view", "technical"),
            ("Take me to vulnerability backlog", "technical"),
            ("Overview of enterprise risk", "executive"),
            ("Open executive dashboard", "executive"),
            ("Show CISO executive overview", "executive"),
            ("Open regulatory compliance crosswalk", "executive"),
        ],
    )
    def test_ai_navigate_routing(self, command: str, expected_tab: str):
        with TestClient(app) as client:
            resp = client.post("/api/v1/ai/navigate", json={"command": command})
            assert resp.status_code == 200, f"Navigation failed for '{command}': {resp.text}"
            data = resp.json()

            validated = AINavigateResponse.model_validate(data)
            assert (
                validated.target_tab == expected_tab
            ), f"Expected '{expected_tab}' for command '{command}', got '{validated.target_tab}'"
            assert validated.action_type in ("switch_tab", "tab_switch")
            assert len(validated.actions) >= 1
            assert validated.actions[0].target_tab == expected_tab


class TestChallenger2InjectAttackContract:
    """Empirically tests POST /api/v1/demo/inject-attack across all 6 attack types and modern devices."""

    ATTACK_VECTORS = [
        ("ddos_surge", "Executive iPhone 15 Pro", "BC-API-GW-01", "VND-CLDF-WAF", "CTRL-WAF"),
        ("ransomware_outage", "External SecOps Laptop", "BC-PAY-GW-01", "VND-CRWD-EDR", "CTRL-EDR"),
        ("sql_data_leak", "CISO MacBook M3", "BC-PII-VAULT-01", "VND-WIZ-CSPM", "CTRL-S3-ENCR"),
        ("credential_stuffing", "SecOps Android Pixel 9", "BC-FLASH-SALE-01", "VND-OKTA-IAM", "CTRL-MFA"),
        ("zero_day_cve", "Executive iPad Air", "BC-FLASH-SALE-01", "VND-CRWD-EDR", "CTRL-EDR"),
        ("cloud_iam_compromise", "Remote Surface Pro 11", "BC-API-GW-01", "VND-OKTA-IAM", "CTRL-MFA"),
    ]

    @pytest.mark.parametrize(
        "attack_type,device_name,target_node,expected_product,expected_control",
        ATTACK_VECTORS,
    )
    def test_all_attack_types_and_modern_devices(
        self,
        attack_type: str,
        device_name: str,
        target_node: str,
        expected_product: str,
        expected_control: str,
    ):
        with TestClient(app) as client:
            payload = {
                "attack_type": attack_type,
                "target_node": target_node,
                "intensity": 5.0,
                "source_device": device_name,
            }
            resp = client.post("/api/v1/demo/inject-attack", json=payload)
            assert resp.status_code == 200, f"Attack injection failed: {resp.text}"
            data = resp.json()

            # Schema validation
            validated = AttackInjectionResponse.model_validate(data)
            assert validated.success is True
            assert validated.status == "INJECTED"
            assert validated.source_device == device_name
            assert validated.target_node == target_node

            # Surge calculations & EAL deltas
            assert validated.tef_spike_multiplier > 1.0
            assert validated.spiked_tef > validated.nominal_tef
            assert validated.total_surge_inr > 0
            assert validated.eal_delta > 0
            assert validated.spiked_eal_inr > validated.baseline_eal_inr
            assert (
                abs(validated.spiked_eal_inr - (validated.baseline_eal_inr + validated.total_surge_inr))
                < 1.0
            )

            # Posture degradation
            assert validated.posture_after < validated.posture_before
            assert validated.posture_degradation_pts > 0
            assert validated.posture_after >= 0.0

            # Mathematical risk bounds (EAL < VaR90 < VaR95 < VaR99)
            assert validated.spiked_eal_inr < validated.var_90_inr < validated.var_95_inr < validated.var_99_inr

            # Vendor mitigation recommendations
            assert validated.recommended_product_id == expected_product
            assert validated.recommended_control_id == expected_control
            assert len(validated.recommended_countermeasure) > 0
            assert validated.neutralization_efficacy_pct > 90.0

            # Verify reset after attack
            reset_resp = client.post("/api/v1/demo/reset-attack")
            assert reset_resp.status_code == 200
            reset_data = reset_resp.json()
            validated_reset = ResetAttackResponse.model_validate(reset_data)
            assert validated_reset.success is True
            assert validated_reset.active_attack is False
            assert validated_reset.current_eal == validated_reset.baseline_eal


class TestChallenger2TelemetryTickerContract:
    """Empirically tests GET /api/v1/demo/telemetry-ticker for stochastic variations and bounds."""

    def test_stochastic_variation_and_bounds(self):
        with TestClient(app) as client:
            readings: List[TelemetryTickerResponse] = []
            for _ in range(12):
                resp = client.get("/api/v1/demo/telemetry-ticker")
                assert resp.status_code == 200, f"Ticker failed: {resp.text}"
                data = resp.json()
                validated = TelemetryTickerResponse.model_validate(data)
                readings.append(validated)

            # Check bounds on all readings
            for r in readings:
                assert r.threat_level in ("NORMAL", "ELEVATED", "CRITICAL_ATTACK_ACTIVE")
                assert 10_000.0 < r.eps_current < 25_000.0, f"EPS out of bounds: {r.eps_current}"
                assert 5.0 < r.tef_current < 30.0, f"TEF out of bounds: {r.tef_current}"
                assert 5 <= r.active_alerts_count <= 25, f"Alert count out of bounds: {r.active_alerts_count}"
                assert 0.0 <= r.posture_score <= 100.0, f"Posture score out of bounds: {r.posture_score}"
                assert r.current_eal_inr < r.var_90_inr < r.var_95_inr < r.var_99_inr

            # Verify stochastic variations exist (readings are not static constants)
            tef_values = {round(r.tef_current, 3) for r in readings}
            eps_values = {round(r.eps_current, 1) for r in readings}
            assert len(tef_values) > 1, f"TEF values lack stochastic jitter: {tef_values}"
            assert len(eps_values) > 1, f"EPS values lack stochastic jitter: {eps_values}"

    def test_ticker_during_active_attack(self):
        with TestClient(app) as client:
            # Inject attack
            inject_resp = client.post(
                "/api/v1/demo/inject-attack",
                json={
                    "attack_type": "ddos_surge",
                    "target_node": "BC-API-GW-01",
                    "intensity": 6.0,
                    "source_device": "Executive iPhone 15 Pro",
                },
            )
            assert inject_resp.status_code == 200

            # Poll ticker during active attack
            ticker_resp = client.get("/api/v1/demo/telemetry-ticker")
            assert ticker_resp.status_code == 200
            ticker_data = ticker_resp.json()
            r = TelemetryTickerResponse.model_validate(ticker_data)

            assert r.threat_level == "CRITICAL_ATTACK_ACTIVE"
            assert r.has_active_attack is True
            assert r.attack_type == "ddos_surge"
            assert r.target_node == "BC-API-GW-01"
            assert r.tef_current > 15.0  # Spiked TEF
            assert r.active_alerts_count >= 20

            # Reset and verify return to normal
            client.post("/api/v1/demo/reset-attack")
            nominal_resp = client.get("/api/v1/demo/telemetry-ticker")
            nominal_data = nominal_resp.json()
            nom_r = TelemetryTickerResponse.model_validate(nominal_data)
            assert nom_r.threat_level == "NORMAL"
            assert nom_r.has_active_attack is False


class TestChallenger2TerminologyZeroJury:
    """Scans all source, template, script, and style files for zero 'jury' occurrences."""

    def test_zero_jury_in_src_and_run_server(self):
        root_dir = Path(__file__).resolve().parent.parent.parent
        src_dir = root_dir / "src"
        run_server_file = root_dir / "run_server.py"

        extensions = (".py", ".html", ".js", ".css")
        matches: List[str] = []

        # Scan src/
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(extensions):
                    file_path = Path(root) / file
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for line_no, line in enumerate(content.splitlines(), start=1):
                        if re.search(r"\bjury\b", line, re.IGNORECASE):
                            rel_path = file_path.relative_to(root_dir)
                            matches.append(f"{rel_path}:{line_no}: {line.strip()}")

        # Scan run_server.py
        if run_server_file.exists():
            content = run_server_file.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(content.splitlines(), start=1):
                if re.search(r"\bjury\b", line, re.IGNORECASE):
                    matches.append(f"run_server.py:{line_no}: {line.strip()}")

        assert len(matches) == 0, f"Found 'jury' occurrences:\n" + "\n".join(matches)
