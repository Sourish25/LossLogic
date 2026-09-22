"""
tests/unit/test_demo_backend_m1.py - Verification Suite for BharatCart Topology, Attack Engine, and API Routes.
"""

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.routes import CANONICAL_CONTROLS
from src.optimization.models import ThreatVectorEnum
from src.telemetry.attack_engine import (
    AttackType,
    DemoAttackStateManager,
    calculate_attack_impact,
)
from src.telemetry.generator import ApexEnterpriseGenerator


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


class TestBharatCartTopologyAndGenerator:
    """Verify BharatCart scenario nodes, services, DAG edges, and invariant preservation."""

    def test_generator_assets_baseline_vs_bharatcart(self):
        gen = ApexEnterpriseGenerator(seed=42)
        # Baseline invariant: exactly 65 assets
        assets_default = gen.generate_assets()
        assert len(assets_default) == 65

        # With BharatCart: 65 + 4 = 69 assets
        assets_with_bc = gen.generate_assets(include_bharatcart=True)
        assert len(assets_with_bc) == 69

        # BharatCart individual asset generator
        bc_assets = gen.generate_bharatcart_assets()
        assert len(bc_assets) == 4
        bc_ids = {a.asset_id for a in bc_assets}
        assert bc_ids == {"BC-API-GW-01", "BC-FLASH-SALE-01", "BC-PAY-GW-01", "BC-PII-VAULT-01"}

    def test_bharatcart_services(self):
        gen = ApexEnterpriseGenerator(seed=42)
        bc_svcs = gen.generate_bharatcart_services()
        assert len(bc_svcs) == 3
        svc_ids = {s.service_id for s in bc_svcs}
        assert svc_ids == {"SVC-BC-CHECKOUT", "SVC-BC-FLASHSALE", "SVC-BC-PORTAL"}

    def test_bharatcart_dataset_and_dag_edges(self):
        gen = ApexEnterpriseGenerator(seed=42)
        assets, findings, graph = gen.generate_bharatcart_dataset()
        assert len(assets) == 4
        assert len(findings) == 4
        assert graph.is_valid_dag() is True

        # Check BharatCart chain dependencies:
        # BC-API-GW-01 -> BC-FLASH-SALE-01 -> BC-PAY-GW-01 -> BC-PII-VAULT-01
        assert ("BC-API-GW-01", "BC-FLASH-SALE-01") in graph.graph.edges
        assert ("BC-FLASH-SALE-01", "BC-PAY-GW-01") in graph.graph.edges
        assert ("BC-PAY-GW-01", "BC-PII-VAULT-01") in graph.graph.edges

        # Failure of BC-PII-VAULT-01 percolates upstream to all 3 nodes and services
        perc = graph.percolate_failure("BC-PII-VAULT-01")
        assert len(perc.impacted_services) == 3
        assert "BC-PAY-GW-01" in perc.impacted_assets
        assert "BC-FLASH-SALE-01" in perc.impacted_assets
        assert "BC-API-GW-01" in perc.impacted_assets


class TestAttackEngineDynamics:
    """Verify attack calculations, exact +₹4.58 Cr baseline calibration, and posture drops."""

    @pytest.mark.parametrize("atk_type", [
        AttackType.DDOS_SURGE,
        AttackType.RANSOMWARE_OUTAGE,
        AttackType.SQL_DATA_LEAK,
        AttackType.CREDENTIAL_STUFFING,
    ])
    def test_baseline_surge_calibration_at_default_intensity(self, atk_type):
        res = calculate_attack_impact(attack_type=atk_type, intensity=5.0)
        # Exact +₹4.58 Cr baseline surge (45,800,000.0 INR)
        assert res.total_surge_inr == 45_800_000.0
        assert res.spiked_eal_inr == 48_200_000.0 + 45_800_000.0
        assert res.direct_loss_inr + res.cascading_loss_inr == pytest.approx(45_800_000.0, abs=0.01)

        # Posture drop must be bounded between 25.0 and 50.0 points
        assert 25.0 <= res.posture_degradation_pts <= 50.0
        assert res.posture_after == pytest.approx(res.posture_before - res.posture_degradation_pts, abs=0.1)

        # Actionable countermeasure
        assert res.recommended_control_id in {"CTRL-WAF", "CTRL-EDR", "CTRL-S3-ENCR", "CTRL-MFA"}
        assert res.neutralization_efficacy > 0.90

    def test_attack_impact_with_active_defense(self):
        # Without defense
        res_undefended = calculate_attack_impact(AttackType.DDOS_SURGE, intensity=5.0, active_defense_immunity=0.0)
        # With 99.4% Cloudflare defense
        res_defended = calculate_attack_impact(AttackType.DDOS_SURGE, intensity=5.0, active_defense_immunity=0.994)

        assert res_defended.total_surge_inr < res_undefended.total_surge_inr
        assert res_defended.spiked_eal_inr < res_undefended.spiked_eal_inr

    def test_state_manager_inject_and_reset(self):
        sm = DemoAttackStateManager()
        sm.reset()
        assert sm.current_eal_inr == 48_200_000.0
        assert sm.current_posture == 84.6
        assert sm.active_attack is None

        # Inject attack
        res = sm.inject(AttackType.RANSOMWARE_OUTAGE, intensity=5.0)
        assert sm.current_eal_inr > 48_200_000.0
        assert sm.current_posture < 84.6
        assert sm.active_attack is not None

        # Telemetry pulse shows active attack
        pulse = sm.get_telemetry_pulse()
        assert pulse["has_active_attack"] is True
        assert pulse["threat_level"] == "CRITICAL_ATTACK_ACTIVE"
        assert pulse["events_per_second"] > 0

        # Reset
        reset_res = sm.reset()
        assert reset_res["success"] is True
        assert sm.current_eal_inr == 48_200_000.0
        assert sm.current_posture == 84.6


class TestDemoApiRoutes:
    """Verify REST contracts for /demo and /vendor-benchmark endpoints."""

    def test_inject_attack_endpoint(self, client):
        # Clean state first
        client.post("/api/v1/demo/reset-attack")

        # Call POST /api/v1/demo/inject-attack
        resp = client.post(
            "/api/v1/demo/inject-attack",
            json={
                "attack_type": "ddos_surge",
                "target_node": "BC-API-GW-01",
                "intensity": 5.0,
                "source_device": "SecOps iPhone 15 Pro",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["attack_type"] == "ddos_surge"
        assert data["target_node"] == "BC-API-GW-01"
        assert data["eal_surge_inr"] == 45_800_000.0
        assert data["new_eal_inr"] == 48_200_000.0 + 45_800_000.0
        assert 25.0 <= data["posture_degradation_pts"] <= 50.0
        assert data["recommended_control_id"] == "CTRL-WAF"

    def test_inject_attack_validation_error(self, client):
        # Invalid intensity > 10.0
        resp = client.post(
            "/api/v1/demo/inject-attack",
            json={"attack_type": "ddos_surge", "intensity": 50.0},
        )
        assert resp.status_code == 422

        # Invalid attack type
        resp = client.post(
            "/api/v1/demo/inject-attack",
            json={"attack_type": "invalid_attack_name"},
        )
        assert resp.status_code == 422

    def test_telemetry_ticker_endpoint(self, client):
        resp = client.get("/api/v1/demo/telemetry-ticker")
        assert resp.status_code == 200
        data = resp.json()
        assert "timestamp" in data
        assert data["events_per_second"] > 1000.0
        assert data["threat_event_frequency"] > 0.0
        assert data["active_alerts_count"] >= 0
        assert "overall_threat_level" in data

    def test_reset_attack_endpoint(self, client):
        # Inject an attack first
        client.post("/api/v1/demo/inject-attack", json={"attack_type": "sql_data_leak", "intensity": 4.0})
        # Reset
        resp = client.post("/api/v1/demo/reset-attack")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["current_eal"] == 48_200_000.0
        assert data["posture_score"] == 84.6

    def test_vendor_benchmark_matrix_endpoint(self, client):
        resp = client.get("/api/v1/vendor-benchmark/matrix?currency=INR")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["vendors"]) == 5
        assert set(data["categories"]) == {"EDR", "WAF", "IAM", "CSPM"}
        vendor_names = {v["vendor_name"] for v in data["vendors"]}
        assert "CrowdStrike" in vendor_names
        assert "Cloudflare" in vendor_names
        assert "Okta" in vendor_names
        assert "Wiz" in vendor_names
        assert "Microsoft" in vendor_names

        # Each vendor must have future_threat_shields
        for v in data["vendors"]:
            assert len(v["future_threat_shields"]) >= 3
            assert v["overall_coverage_rating"] > 80.0

    def test_vendor_virtual_purchase_endpoint(self, client):
        # Reset state first
        client.post("/api/v1/demo/reset-attack")

        # Purchase CrowdStrike
        resp = client.post(
            "/api/v1/vendor-benchmark/purchase",
            json={"vendor_id": "VND-CRWD-EDR", "currency": "INR"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "PURCHASED"
        assert data["vendor_id"] == "VND-CRWD-EDR"
        assert data["allocated_spend"] > 0.0
        assert data["residual_eal"] < data["baseline_eal"]
        assert data["security_upgrade_pct"] > 0.0
        assert data["security_factor_score"] > 84.6

        # Invalid vendor purchase returns 404
        resp_bad = client.post(
            "/api/v1/vendor-benchmark/purchase",
            json={"vendor_id": "UNKNOWN_VENDOR_999"},
        )
        assert resp_bad.status_code == 404


class TestCanonicalControlsEnrichment:
    """Verify CANONICAL_CONTROLS is fully enriched with ThreatShields across all 5 vectors."""

    def test_canonical_controls_shields_and_vectors(self):
        assert len(CANONICAL_CONTROLS) >= 6

        observed_vectors = set()
        for ctrl in CANONICAL_CONTROLS:
            assert len(ctrl.future_threat_shields) >= 2, f"Control {ctrl.control_id} lacks threat shields"
            for shield in ctrl.future_threat_shields:
                assert 0.0 <= shield.future_immunity_pct <= 100.0
                assert len(shield.neutralized_attack_types) > 0
                assert len(shield.protective_mechanism) > 0
                observed_vectors.add(shield.threat_vector)

        # All 5 canonical threat vectors must be represented across canonical controls
        assert ThreatVectorEnum.ZERO_DAY_RCE in observed_vectors
        assert ThreatVectorEnum.RANSOMWARE_LATERAL in observed_vectors
        assert ThreatVectorEnum.VOLUMETRIC_DDOS in observed_vectors
        assert ThreatVectorEnum.CREDENTIAL_STUFFING in observed_vectors
        assert ThreatVectorEnum.DATA_EXFILTRATION in observed_vectors
