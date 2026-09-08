"""
tests/api/test_api_contracts.py - Comprehensive API Contract Tests for FastAPI Backend.
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app


@pytest.fixture
def client() -> TestClient:
    """TestClient instance bound to the active FastAPI app."""
    return TestClient(app)


class TestApiContracts:
    """Validates public REST API schemas, status codes, and invariant behaviors."""

    def test_health_check_endpoint(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "timestamp" in data

    def test_executive_dashboard_endpoint_inr(self, client: TestClient):
        response = client.get("/api/v1/dashboard/executive?currency=INR")
        assert response.status_code == 200
        data = response.json()
        assert data["currency"] == "INR"
        assert data["total_eal"] > 0.0
        assert data["var_90"] < data["var_95"] < data["var_99"]
        assert 0.0 <= data["compliance_pct"] <= 100.0
        assert len(data["top_loss_drivers"]) > 0
        assert data["recommended_rosi"] > 0.0
        assert len(data["loss_exceedance_curve"]) > 0
        assert "day_30_eal" in data["trajectory"]

    def test_executive_dashboard_endpoint_usd(self, client: TestClient):
        response = client.get("/api/v1/dashboard/executive?currency=USD")
        assert response.status_code == 200
        data = response.json()
        assert data["currency"] == "USD"
        assert data["total_eal"] > 0.0
        assert data["var_90"] < data["var_95"] < data["var_99"]

    def test_technical_dashboard_endpoint(self, client: TestClient):
        response = client.get("/api/v1/dashboard/technical")
        assert response.status_code == 200
        data = response.json()
        assert "vulnerability" in data["domain_counts"]
        assert "siem" in data["domain_counts"]
        assert "iam" in data["domain_counts"]
        assert "edr" in data["domain_counts"]
        assert "cspm" in data["domain_counts"]
        assert data["critical_findings_count"] >= 1
        assert len(data["backlog"]) >= 5
        assert "ISO_27001" in data["compliance_gaps"]

    def test_risk_simulate_endpoint(self, client: TestClient):
        payload = {"iterations": 2000, "seed": 42, "currency": "INR"}
        response = client.post("/api/v1/risk/simulate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["eal"] > 0.0
        assert data["var_90"] <= data["var_95"] <= data["var_99"]
        assert data["execution_time_ms"] >= 0.0

    def test_what_if_endpoint_mitigation(self, client: TestClient):
        payload = {
            "implemented_control_ids": ["CTRL-MFA", "CTRL-PATCH"],
            "delay_days": 0,
            "currency": "INR"
        }
        response = client.post("/api/v1/decision/what-if", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_delta"] > 0.0
        assert data["simulated_eal"] < data["baseline_eal"]
        assert data["risk_reduction_pct"] > 0.0
        assert "narrative" in data

    def test_what_if_endpoint_delayed_remediation(self, client: TestClient):
        payload = {
            "implemented_control_ids": [],
            "delay_days": 30,
            "currency": "INR"
        }
        response = client.post("/api/v1/decision/what-if", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["delay_penalty_cost"] > 0.0

    def test_nlq_query_endpoint(self, client: TestClient):
        payload = {"query": "What is our highest financial cyber risk today?", "currency": "INR"}
        response = client.post("/api/v1/decision/nlq", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["query"] == payload["query"]
        assert data["intent"] in ["HIGHEST_RISK", "TOP_LOSS_DRIVERS", "UNKNOWN"]
        assert len(data["narrative_answer"]) > 10

    def test_optimize_portfolio_endpoint(self, client: TestClient):
        payload = {"budget": 10000000.0, "currency": "INR", "include_frontier": True}
        response = client.post("/api/v1/optimize/portfolio", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["allocated_spend"] <= payload["budget"]
        assert data["risk_mitigated"] > 0.0
        assert data["residual_eal"] >= 0.0
        assert len(data["selected_controls"]) > 0
        assert data["portfolio_rosi"] > 0.0
        assert data["efficiency_frontier"] is not None

    def test_optimize_alias_endpoint(self, client: TestClient):
        payload = {"budget": 5000000.0, "currency": "INR", "include_frontier": False}
        response = client.post("/api/v1/optimize", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["allocated_spend"] <= payload["budget"]

    def test_compliance_matrix_endpoint(self, client: TestClient):
        response = client.get("/api/v1/compliance/matrix?currency=INR")
        assert response.status_code == 200
        data = response.json()
        assert "composite_compliance_pct" in data
        assert 0.0 <= data["composite_compliance_pct"] <= 100.0
        assert "ISO_27001" in data["frameworks"]
        assert "NIST_CSF" in data["frameworks"]
        assert "CIS_V8" in data["frameworks"]
        assert "RBI_CSF" in data["frameworks"]
        assert "SEBI_CSCRF" in data["frameworks"]

    def test_telemetry_drilldown_endpoint(self, client: TestClient):
        for dom in ["vulnerability", "siem", "iam", "edr", "cspm"]:
            response = client.get(f"/api/v1/telemetry/drilldown/{dom}")
            assert response.status_code == 200
            data = response.json()
            assert data["domain"] == dom
            assert data["count"] >= 1
            assert len(data["findings"]) == data["count"]

    def test_invalid_request_yields_422(self, client: TestClient):
        response = client.post("/api/v1/optimize", json={"budget": "not-a-number"})
        assert response.status_code == 422

    def test_root_dashboard_html(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "LossLogic" in response.text
        assert "liquid-canvas" in response.text
        assert "liquid-nav" in response.text

    def test_static_assets_serving(self, client: TestClient):
        css_resp = client.get("/static/css/dashboard.css")
        assert css_resp.status_code == 200
        assert "backdrop-filter" in css_resp.text

        js_resp = client.get("/static/js/dashboard.js")
        assert js_resp.status_code == 200
        assert "initLiquidCanvas" in js_resp.text

