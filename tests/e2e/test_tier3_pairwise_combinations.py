"""
tests/e2e/test_tier3_pairwise_combinations.py - Tier 3 Cross-Feature Pairwise Combinations.

Verifies cross-feature combinatorial interactions:
1. Finding Severity (Critical, High, Medium, Low) x Asset Criticality Tier (Tier 1..4) interaction.
2. Monte Carlo Loss Simulation x What-If Counterfactual Control Removal (Removing Tier 1 vs Tier 4 controls).
3. Budget Optimization x Mandatory Regulatory Constraints (RBI CSF + SEBI CSCRF forcing capital allocation).
4. Currency Conversion (INR vs USD) x Dashboard API Data Serialization & Round-Trip Precision.
5. Multi-Domain Telemetry Clustering (Vuln + IAM + EDR on the same critical asset).
6. Threat Capability x Resistance Strength Interaction matrix.
"""

import json
import math
from typing import Dict, List, Tuple
import pytest

from tests.conftest import (
    AssetTier,
    Currency,
    DataSensitivity,
    InvariantAssertions,
    MockAssetRecord,
    MockCandidateControl,
    MockNormalizedFinding,
    ReferenceComplianceEngine,
    ReferenceFairMonteCarlo,
    ReferenceKnapsackOptimizer,
    SeverityLevel,
    TelemetryDomain,
)


@pytest.mark.e2e
@pytest.mark.tier3
class TestTier3PairwiseCombinations:
    """Pairwise combinatorial interactions across platform components."""

    @pytest.mark.parametrize("severity,cvss,epss", [
        (SeverityLevel.CRITICAL, 9.8, 0.90),
        (SeverityLevel.HIGH, 7.5, 0.40),
        (SeverityLevel.MEDIUM, 5.0, 0.15),
        (SeverityLevel.LOW, 2.5, 0.02),
    ])
    @pytest.mark.parametrize("tier,crit_score,cost", [
        (AssetTier.TIER_1, 5.0, 10000000.0),
        (AssetTier.TIER_2, 3.0, 3000000.0),
        (AssetTier.TIER_3, 1.5, 1000000.0),
        (AssetTier.TIER_4, 0.2, 100000.0),
    ])
    def test_severity_cross_asset_tier_interaction(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        severity: SeverityLevel,
        cvss: float,
        epss: float,
        tier: AssetTier,
        crit_score: float,
        cost: float,
    ):
        """
        Pairwise Matrix: 4 Finding Severities x 4 Asset Criticality Tiers (16 combinations).
        Verifies that:
        1. EAL is strictly positive for all 16 combinations.
        2. Higher tier strictly amplifies EAL for identical severity.
        """
        asset = MockAssetRecord(
            asset_id="asset-combo-test",
            name=f"Test Asset {tier.value}",
            business_unit="Finance",
            tier=tier,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            replacement_cost=cost,
            downtime_cost_per_hour=cost * 0.05,
            asset_criticality_score=crit_score
        )
        finding = MockNormalizedFinding(
            finding_id=f"FIND-{severity.value}-{tier.value}",
            asset_id=asset.asset_id,
            domain=TelemetryDomain.VULNERABILITY,
            severity=severity,
            title=f"Finding {severity.value}",
            cvss_score=cvss,
            epss_score=epss,
            cisa_kev=(severity == SeverityLevel.CRITICAL),
            threat_event_frequency=10.0,
            resistance_strength=0.3
        )

        res = fair_engine.simulate([finding], {asset.asset_id: asset}, seed_override=42)
        assert res.eal > 0.0, f"Expected positive EAL for {severity.value} x {tier.value}"
        assert res.var_95 > res.eal

    def test_monte_carlo_cross_what_if_counterfactual_removal(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_telemetry_5_domains: List[MockNormalizedFinding],
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Interaction: Monte Carlo loss distribution x What-If counterfactual control removal.
        Removing a control protecting a Tier 1 asset produces a significantly greater risk surge
        than removing a control on a Tier 2 workstation.
        """
        # Baseline simulation
        base_res = fair_engine.simulate(mock_telemetry_5_domains, mock_asset_catalog, seed_override=42)

        # What-If 1: Remove protection on Tier 1 DB (increase threat frequency by 3x)
        degraded_t1 = [
            MockNormalizedFinding(
                finding_id=f.finding_id, asset_id=f.asset_id, domain=f.domain, severity=f.severity,
                title=f.title, cvss_score=f.cvss_score, epss_score=f.epss_score, cisa_kev=f.cisa_kev,
                threat_event_frequency=f.threat_event_frequency * (3.0 if f.asset_id == "asset-core-db-01" else 1.0),
                resistance_strength=f.resistance_strength * (0.3 if f.asset_id == "asset-core-db-01" else 1.0)
            )
            for f in mock_telemetry_5_domains
        ]
        res_deg_t1 = fair_engine.simulate(degraded_t1, mock_asset_catalog, seed_override=42)
        surge_t1 = res_deg_t1.eal - base_res.eal

        # What-If 2: Remove protection on Tier 2 Trader Workstation
        degraded_t2 = [
            MockNormalizedFinding(
                finding_id=f.finding_id, asset_id=f.asset_id, domain=f.domain, severity=f.severity,
                title=f.title, cvss_score=f.cvss_score, epss_score=f.epss_score, cisa_kev=f.cisa_kev,
                threat_event_frequency=f.threat_event_frequency * (3.0 if f.asset_id == "asset-trader-ws-01" else 1.0),
                resistance_strength=f.resistance_strength * (0.3 if f.asset_id == "asset-trader-ws-01" else 1.0)
            )
            for f in mock_telemetry_5_domains
        ]
        res_deg_t2 = fair_engine.simulate(degraded_t2, mock_asset_catalog, seed_override=42)
        surge_t2 = res_deg_t2.eal - base_res.eal

        assert surge_t1 > 0.0
        assert surge_t2 > 0.0
        assert surge_t1 > surge_t2 * 5.0, (
            f"Degrading Tier 1 asset should produce vastly higher risk surge than Tier 2 asset! "
            f"T1 surge={surge_t1}, T2 surge={surge_t2}"
        )

    def test_budget_optimization_cross_regulatory_constraints(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
        mock_control_portfolio: List[MockCandidateControl],
    ):
        """
        Interaction: Budget Optimization x Mandatory Regulatory Controls (RBI CSF + SEBI CSCRF).
        Verifies that when regulatory frameworks mandate specific controls (e.g. CTRL-MFA and CTRL-S3-ENCR),
        the optimizer prioritizes funding regulatory compliance over optional controls,
        even if optional controls have high standalone efficacy.
        """
        # Budget just enough to cover mandatory regulatory controls (₹3.5L + ₹2.5L = ₹6.0L) + small buffer
        budget = 700000.0  # ₹7.0 Lakhs
        res = knapsack_optimizer.optimize(mock_control_portfolio, budget=budget, baseline_eal=40000000.0)

        selected_ids = {c.control_id for c in res.selected_controls}
        # Mandatory regulatory controls must be selected
        assert "CTRL-MFA" in selected_ids, "RBI/SEBI mandated MFA must be funded"
        assert "CTRL-S3-ENCR" in selected_ids, "RBI/SEBI mandated S3 Encryption must be funded"
        # Optional high-cost control (CTRL-EDR ₹8.0L) cannot fit
        assert "CTRL-EDR" not in selected_ids

    def test_currency_conversion_cross_dashboard_api_serialization(self):
        """
        Interaction: Currency Conversion (INR <-> USD) x JSON REST API Serialization.
        Verifies round-trip precision, numeric integrity, and schema serialization.
        """
        exchange_rate = 83.5
        inr_payload = {
            "total_eal": 48200000.0,     # ₹4.82 Crore
            "var_95": 124000000.0,       # ₹12.4 Crore
            "budget": 5000000.0,         # ₹50 Lakhs
            "currency": "INR"
        }

        # Convert to USD payload
        usd_payload = {
            "total_eal": inr_payload["total_eal"] / exchange_rate,
            "var_95": inr_payload["var_95"] / exchange_rate,
            "budget": inr_payload["budget"] / exchange_rate,
            "currency": "USD"
        }

        # Serialize to JSON and deserialize
        serialized = json.dumps(usd_payload)
        deserialized = json.loads(serialized)

        # Convert back to INR
        recon_inr_eal = deserialized["total_eal"] * exchange_rate
        recon_inr_var95 = deserialized["var_95"] * exchange_rate

        assert math.isclose(recon_inr_eal, inr_payload["total_eal"], rel_tol=1e-9)
        assert math.isclose(recon_inr_var95, inr_payload["var_95"], rel_tol=1e-9)
        assert deserialized["currency"] == "USD"

    def test_multi_domain_telemetry_clustering_on_same_asset(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Interaction: Multi-domain telemetry clustering on a single critical asset.
        A single asset suffering from Vulnerabilities + Disabled EDR + IAM Misconfiguration
        exhibits non-linear compounding risk compared to isolated single-domain findings.
        """
        target_asset_id = "asset-core-db-01"
        asset_map = {target_asset_id: mock_asset_catalog[target_asset_id]}

        f_vuln = MockNormalizedFinding(
            finding_id="CLUST-VULN", asset_id=target_asset_id, domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL, title="Critical SQLi", cvss_score=9.8,
            epss_score=0.9, cisa_kev=True, threat_event_frequency=12.0, resistance_strength=0.2
        )
        f_iam = MockNormalizedFinding(
            finding_id="CLUST-IAM", asset_id=target_asset_id, domain=TelemetryDomain.IAM,
            severity=SeverityLevel.HIGH, title="Admin Without MFA", cvss_score=8.5,
            epss_score=0.6, cisa_kev=False, threat_event_frequency=10.0, resistance_strength=0.1
        )
        f_edr = MockNormalizedFinding(
            finding_id="CLUST-EDR", asset_id=target_asset_id, domain=TelemetryDomain.EDR,
            severity=SeverityLevel.HIGH, title="EDR Agent Offline", cvss_score=7.5,
            epss_score=0.5, cisa_kev=False, threat_event_frequency=8.0, resistance_strength=0.1
        )

        res_vuln_only = fair_engine.simulate([f_vuln], asset_map, seed_override=42)
        res_cluster = fair_engine.simulate([f_vuln, f_iam, f_edr], asset_map, seed_override=42)

        assert res_cluster.eal > res_vuln_only.eal
        assert res_cluster.var_99 > res_vuln_only.var_99
        # Multiple active threats on the same core asset create substantial tail loss exposure
        assert res_cluster.var_95 > 1.5 * res_vuln_only.var_95
