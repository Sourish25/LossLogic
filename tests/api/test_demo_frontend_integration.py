"""
tests/api/test_demo_frontend_integration.py - Full E2E Integration Tests for Live Hackathon Demonstration (R1-R6).

Validates:
- Real-time HTML template rendering with all live demo and jury components.
- Static assets (CSS and JS) delivery and critical client-side hooks.
- Attack injection against BharatCart topology and EAL/TEF financial spikes.
- Live SOC telemetry ticker dynamic pulse.
- CEO vendor benchmarking catalog and future threat shields.
- One-click virtual vendor procurement and SUP % computation.
- Clean simulation reset restoring nominal conditions.
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app


@pytest.fixture
def client() -> TestClient:
    """TestClient instance bound to the active FastAPI app."""
    return TestClient(app)


class TestDemoFrontendIntegration:
    """Validates end-to-end integration of Live Jury Demo, BharatCart, and Vendor Matrix."""

    def test_dashboard_html_contains_all_jury_demo_components(self, client: TestClient):
        """Verify the main dashboard HTML contains all required live demo DOM elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        # 1. Navigation & Ticker (2-Tab Segmented Navigation)
        assert 'data-tab="executive"' in html
        assert 'data-tab="technical"' in html
        assert 'data-tab="demo"' not in html
        assert 'id="soc-ticker-banner"' in html
        assert 'id="ticker-eps"' in html
        assert 'id="ticker-tef"' in html
        assert 'id="ticker-status"' in html

        # 2. Attack Alert Banner
        assert 'id="attack-alert-banner"' in html
        assert 'id="aab-vector"' in html
        assert 'id="aab-loss-surge"' in html
        assert 'id="btn-alert-mitigate"' in html

        # 3. Standalone Live Jury Demo Tab is Sunsetted
        assert 'id="tab-demo"' not in html
        assert 'id="tab-executive"' in html
        assert 'id="tab-technical"' in html

        # 4. Global Persistent Live Analytics HUD (Visible Across Views)
        assert ('id="persistent-risk-hud"' in html or 'id="persistent-hud"' in html or 'persistent-hud-strip' in html)
        assert 'id="posture-meter-bar"' in html
        assert 'id="demo-posture-val"' in html
        assert 'id="demo-rf-val"' in html
        assert 'id="demo-rf-indicator"' in html
        assert 'id="demo-sup-val"' in html
        assert 'SUP = (Risk Mitigated / Baseline EAL)' in html
        assert 'id="demo-eal-val"' in html
        assert 'id="demo-shields-val"' in html

        # 5. BharatCart Attack Simulator & Remote cURL Box (Embedded in Technical SecOps View)
        assert ('BharatCart Threat Simulator' in html or 'BharatCart Cyber Threat Simulator' in html or 'BharatCart Multi-Laptop Attack Simulator' in html)
        assert 'id="demo-target-node"' in html
        assert 'data-attack="DDOS_TRAFFIC_SURGE"' in html
        assert 'data-attack="RANSOMWARE_OUTAGE"' in html
        assert 'data-attack="SQL_DATA_EXFILTRATION"' in html
        assert 'data-attack="CREDENTIAL_STUFFING"' in html
        assert 'id="curl-command-display"' in html
        assert 'id="btn-copy-curl"' in html
        assert 'id="demo-terminal-feed"' in html
        assert 'id="btn-reset-demo"' in html

        # 6. CEO Vendor Benchmarking Grid (Embedded in Executive View)
        assert 'CEO Vendor Benchmarking & Virtual Procurement' in html
        assert 'id="vss-total-spend"' in html
        assert 'id="vss-count"' in html
        assert 'id="vendor-benchmark-cards"' in html

        # 7. Future Threat Immunity Modal
        assert 'id="modal-threat-immunity"' in html
        assert 'id="modal-vendor-name"' in html
        assert 'id="modal-shields-grid"' in html
        assert 'id="btn-modal-procure"' in html

        # 8. Rebranded Executive Copilot Chip
        assert '30-Sec Executive Pitch' in html
        assert '30-Sec Jury Pitch' not in html

    def test_static_css_includes_live_demo_styles(self, client: TestClient):
        """Ensure dashboard.css includes styling rules for live demo components."""
        resp = client.get("/static/css/dashboard.css")
        assert resp.status_code == 200
        css = resp.text

        assert ".soc-ticker-bar" in css
        assert ".attack-alert-banner" in css
        assert ".live-dial-card" in css
        assert ".posture-dial-svg" in css
        assert ".rf-bar-track" in css
        assert ".attack-btn" in css
        assert ".remote-curl-box" in css
        assert ".vendor-card" in css
        assert ".glass-modal-backdrop" in css

    def test_static_js_includes_live_demo_logic(self, client: TestClient):
        """Ensure dashboard.js includes client functions for live attacks and procurement."""
        resp = client.get("/static/js/dashboard.js")
        assert resp.status_code == 200
        js = resp.text

        assert "initDemoSandbox" in js
        assert "fetchTelemetryTicker" in js
        assert "injectAttack" in js
        assert "resetAttack" in js
        assert "fetchVendorCatalog" in js
        assert "purchaseVendor" in js
        assert "openThreatImmunityModal" in js
        assert "updatePostureDial" in js
        assert "updateRiskFactorGauge" in js
        assert "updateSecurityUpgradePct" in js

    def test_remote_curl_attack_injection_lifecycle(self, client: TestClient):
        """Simulate a remote device firing an attack, checking telemetry, and resetting."""
        # Reset state first
        client.post("/api/v1/demo/reset-attack")

        # Step 1: Remote laptop fires DDoS attack via cURL
        payload = {
            "attack_type": "DDOS_TRAFFIC_SURGE",
            "target_node": "gateway-01",
            "intensity": 1.0,
            "source_device": "Remote-SecOps-Laptop"
        }
        inj_resp = client.post("/api/v1/demo/inject-attack", json=payload)
        assert inj_resp.status_code == 200
        inj_data = inj_resp.json()

        assert inj_data["success"] is True
        assert "ddos" in inj_data["attack_type"].lower()
        assert "BC-API-GW-01" in inj_data["target_node"] or "gateway" in inj_data["target_node"].lower()
        assert inj_data["spiked_eal_inr"] > inj_data["baseline_eal_inr"]
        assert inj_data["posture_after"] < inj_data["posture_before"]
        assert "Cloudflare" in inj_data["recommended_countermeasure"] or len(inj_data["recommended_countermeasure"]) > 0

        # Step 2: Telemetry ticker reflects active attack
        ticker_resp = client.get("/api/v1/demo/telemetry-ticker")
        assert ticker_resp.status_code == 200
        ticker_data = ticker_resp.json()

        assert ticker_data["active_attack"] is True
        assert "ddos" in ticker_data["attack_type"].lower()
        assert ticker_data["active_alerts_count"] >= 1
        assert ticker_data["events_per_second"] > 0.0

        # Step 3: Procure countermeasure virtually
        purch_payload = {"vendor_id": "CLOUDFLARE_MAGIC_TRANSIT", "currency": "INR"}
        purch_resp = client.post("/api/v1/vendor-benchmark/purchase", json=purch_payload)
        assert purch_resp.status_code == 200
        purch_data = purch_resp.json()

        assert purch_data["status"] in ("PURCHASED", "ALREADY_PURCHASED")
        assert purch_data["security_upgrade_pct"] > 0.0
        assert purch_data["posture_score"] > inj_data["posture_after"]
        assert purch_data["allocated_spend"] > 0.0

        # Step 4: Reset restores baseline
        reset_resp = client.post("/api/v1/demo/reset-attack")
        assert reset_resp.status_code == 200
        reset_data = reset_resp.json()

        assert reset_data["status"] == "RESET_COMPLETED"
        assert reset_data["active_attack"] is False
        assert reset_data["posture_score"] >= 80.0

    def test_vendor_benchmark_matrix_structure(self, client: TestClient):
        """Validate vendor benchmark matrix provides full future threat shields and ratings."""
        resp = client.get("/api/v1/vendor-benchmark/matrix?currency=INR")
        assert resp.status_code == 200
        data = resp.json()

        assert "vendors" in data
        assert len(data["vendors"]) >= 5

        for v in data["vendors"]:
            assert "vendor_id" in v
            assert "vendor_name" in v
            assert "product_name" in v
            assert "annual_cost" in v
            assert v["annual_cost"] > 0.0
            assert 0.0 <= v["overall_coverage_rating"] <= 100.0
            assert "future_threat_shields" in v
            assert len(v["future_threat_shields"]) >= 2

            for s in v["future_threat_shields"]:
                assert "threat_vector" in s
                assert "neutralization_rate_pct" in s
                assert "proactive_defense_mechanism" in s
                assert 0.0 < s["neutralization_rate_pct"] <= 100.0
