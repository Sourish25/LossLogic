"""
tests/api/test_dynamic_telemetry_jury.py - Automated tests for jury demonstration requirements:
  - Zero-day CVE and Cloud IAM attack injections (R2)
  - Dynamic VaR percentiles and posture drift calculation (R2)
  - Continuous telemetry ticker streaming and background events (R2)
  - Primary API routes and REST aliases (/assets, /quant/simulate, /optimize/allocate) (R3)
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app
from src.telemetry.attack_engine import DemoAttackStateManager, AttackType


@pytest.fixture(autouse=True)
def reset_demo_state():
    """Ensure clean baseline state before each test."""
    manager = DemoAttackStateManager()
    manager.reset()
    yield
    manager.reset()


def test_primary_api_endpoints_return_200():
    """Verify all primary API endpoints and aliases return HTTP 200."""
    with TestClient(app) as client:
        # GET /api/v1/assets
        r_assets = client.get("/api/v1/assets")
        assert r_assets.status_code == 200
        data_assets = r_assets.json()
        assert "assets" in data_assets
        assert data_assets["total_assets"] >= 65

        # POST /api/v1/quant/simulate (alias for /risk/simulate)
        r_quant = client.post("/api/v1/quant/simulate", json={"currency": "INR"})
        assert r_quant.status_code == 200
        data_quant = r_quant.json()
        assert data_quant["eal"] > 0
        assert data_quant["var_90"] < data_quant["var_95"] < data_quant["var_99"]

        # POST /api/v1/optimize/allocate (alias for /optimize/portfolio)
        r_opt = client.post("/api/v1/optimize/allocate", json={"budget": 5000000.0, "currency": "INR"})
        assert r_opt.status_code == 200
        data_opt = r_opt.json()
        assert "selected_controls" in data_opt
        assert data_opt["allocated_spend"] <= 5000000.0

        # GET /api/v1/compliance/matrix
        r_comp = client.get("/api/v1/compliance/matrix?currency=INR")
        assert r_comp.status_code == 200
        data_comp = r_comp.json()
        assert "composite_compliance_pct" in data_comp


def test_zero_day_cve_attack_injection():
    """Verify Zero-Day CVE attack injection recalculates EAL and VaR percentiles."""
    with TestClient(app) as client:
        payload = {
            "attack_type": "zero_day_cve",
            "target_node": "BC-FLASH-SALE-01",
            "intensity": 5.0,
            "source_device": "SecOps-Tester",
        }
        res = client.post("/api/v1/demo/inject-attack", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["attack_type"] == "zero_day_cve"
        assert data["spiked_eal_inr"] > data["baseline_eal_inr"]
        assert data["posture_after"] < data["posture_before"]
        assert data["posture_drift_pct"] < 0
        # Check VaR scaling and invariants
        assert data["var_90_inr"] < data["var_95_inr"] < data["var_99_inr"]
        assert data["spiked_eal_inr"] < data["var_90_inr"]


def test_cloud_iam_compromise_attack_injection():
    """Verify Cloud IAM Compromise attack injection recalculates risk and posture."""
    with TestClient(app) as client:
        payload = {
            "attack_type": "cloud_iam_compromise",
            "target_node": "BC-API-GW-01",
            "intensity": 5.0,
            "source_device": "SecOps-Tester",
        }
        res = client.post("/api/v1/demo/inject-attack", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["attack_type"] == "cloud_iam_compromise"
        assert data["spiked_eal_inr"] > data["baseline_eal_inr"]
        assert data["posture_after"] < data["posture_before"]


def test_telemetry_ticker_dynamic_streaming():
    """Verify telemetry ticker emits dynamic metrics, VaR percentiles, and recent events."""
    with TestClient(app) as client:
        res = client.get("/api/v1/demo/telemetry-ticker")
        assert res.status_code == 200
        data = res.json()
        assert "events_per_second" in data
        assert "threat_event_frequency" in data
        assert "current_eal_inr" in data
        assert "var_90_inr" in data
        assert "var_95_inr" in data
        assert "var_99_inr" in data
        assert data["current_eal_inr"] < data["var_90_inr"] < data["var_95_inr"] < data["var_99_inr"]
        assert isinstance(data["recent_events"], list)
        assert len(data["recent_events"]) > 0
        assert "nodes" in data
        assert len(data["nodes"]) == 4


def test_attack_lifecycle_reset():
    """Verify injecting an attack and resetting restores nominal baseline."""
    with TestClient(app) as client:
        # Inject
        client.post("/api/v1/demo/inject-attack", json={"attack_type": "ddos_surge", "target_node": "BC-API-GW-01"})
        t_spiked = client.get("/api/v1/demo/telemetry-ticker").json()
        assert t_spiked["active_attack"] is True

        # Reset
        res_reset = client.post("/api/v1/demo/reset-attack")
        assert res_reset.status_code == 200
        data_reset = res_reset.json()
        assert data_reset["active_attack"] is False

        # Ticker after reset
        t_nominal = client.get("/api/v1/demo/telemetry-ticker").json()
        assert t_nominal["active_attack"] is False
        assert t_nominal["current_eal_inr"] == pytest.approx(48_200_000.0)
