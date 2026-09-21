"""
tests/unit/test_models_metrics_m1.py - Verification Suite for Milestone M1 Models & Metrics.
"""

import math
import pytest
from src.config import USD_TO_INR_RATE
from src.optimization.models import (
    FrontierPoint,
    OptimizationResult,
    SecurityControl,
    ThreatShield,
    ThreatVectorEnum,
)
from src.optimization.rosi import (
    calculate_net_capital_saved,
    calculate_security_posture_score,
    calculate_security_upgrade_pct,
)
from src.optimization.vendor_benchmarking import (
    VENDOR_CATALOG,
    VendorCategoryEnum,
    VendorProductProfile,
    apply_virtual_vendor_purchase,
    get_ceo_vendor_catalog,
    get_vendor_by_id,
)


class TestThreatModelsAndBackwardCompatibility:
    """Verify ThreatVectorEnum, ThreatShield, and backward compatibility of SecurityControl."""

    def test_threat_vector_enum_members_and_resolution(self):
        assert ThreatVectorEnum.ZERO_DAY_RCE.value == "Zero-Day RCE"
        assert ThreatVectorEnum.RANSOMWARE_LATERAL.value == "Ransomware Lateral Movement"
        assert ThreatVectorEnum.VOLUMETRIC_DDOS.value == "Volumetric DDoS"
        assert ThreatVectorEnum.CREDENTIAL_STUFFING.value == "Credential Stuffing"
        assert ThreatVectorEnum.DATA_EXFILTRATION.value == "Data Exfiltration"

        # Permissive _missing_ lookup
        assert ThreatVectorEnum("ZERO_DAY_RCE") == ThreatVectorEnum.ZERO_DAY_RCE
        assert ThreatVectorEnum("Zero-Day RCE") == ThreatVectorEnum.ZERO_DAY_RCE
        assert ThreatVectorEnum("ransomware_lateral") == ThreatVectorEnum.RANSOMWARE_LATERAL
        assert ThreatVectorEnum("DDOS") == ThreatVectorEnum.VOLUMETRIC_DDOS
        assert ThreatVectorEnum("data_leak") == ThreatVectorEnum.DATA_EXFILTRATION
        assert ThreatVectorEnum("RCE") == ThreatVectorEnum.ZERO_DAY_RCE
        assert ThreatVectorEnum("CREDENTIALS") == ThreatVectorEnum.CREDENTIAL_STUFFING
        with pytest.raises(ValueError):
            ThreatVectorEnum("unknown_threat")

    def test_threat_shield_instantiation_and_aliases(self):
        # Direct canonical instantiation
        shield = ThreatShield(
            threat_vector=ThreatVectorEnum.ZERO_DAY_RCE,
            neutralized_attack_types=["Memory Corruption", "Heap Spray"],
            future_immunity_pct=94.5,
            protective_mechanism="Ring-0 heuristic monitor"
        )
        assert shield.threat_vector == ThreatVectorEnum.ZERO_DAY_RCE
        assert shield.future_immunity_pct == 94.5
        assert len(shield.neutralized_attack_types) == 2
        assert shield.protective_mechanism == "Ring-0 heuristic monitor"

        # Instantiation via aliases (immunity_percentage, protection_mechanism, attack_vector)
        shield_alias = ThreatShield.model_validate({
            "attack_vector": "Volumetric DDoS",
            "immunity_percentage": 99.8,
            "protection_mechanism": "Anycast scrubbing network",
            "neutralized_attack_types": ["SYN Flood", "UDP Reflection"]
        })
        assert shield_alias.threat_vector == ThreatVectorEnum.VOLUMETRIC_DDOS
        assert shield_alias.future_immunity_pct == 99.8
        assert shield_alias.protective_mechanism == "Anycast scrubbing network"

    def test_security_control_backward_compatibility(self):
        # Existing legacy fixture without future_threat_shields
        ctrl = SecurityControl(
            control_id="CTRL-LEGACY",
            name="Legacy Control",
            category="IAM",
            cost_usd=5000.0,
            effectiveness=0.85
        )
        assert ctrl.future_threat_shields == []
        assert ctrl.cost_inr == 5000.0 * USD_TO_INR_RATE
        assert ctrl.get_threat_shield("Zero-Day RCE") is None

        # Enriched control with future_threat_shields
        enriched_ctrl = SecurityControl(
            control_id="CTRL-ENRICHED",
            name="Next-Gen EDR",
            category="Endpoint",
            cost_usd=10000.0,
            future_threat_shields=[
                ThreatShield(
                    threat_vector=ThreatVectorEnum.RANSOMWARE_LATERAL,
                    future_immunity_pct=96.5,
                    protective_mechanism="Host isolation"
                )
            ]
        )
        assert len(enriched_ctrl.future_threat_shields) == 1
        shield = enriched_ctrl.get_threat_shield(ThreatVectorEnum.RANSOMWARE_LATERAL)
        assert shield is not None
        assert shield.future_immunity_pct == 96.5

        # Query by string synonym
        shield_str = enriched_ctrl.get_threat_shield("RANSOMWARE")
        assert shield_str is not None
        assert shield_str.future_immunity_pct == 96.5

    def test_frontier_and_optimization_models_security_upgrade_pct(self):
        fp = FrontierPoint(spend=1000.0, risk_mitigated=5000.0, residual_eal=10000.0, security_upgrade_pct=25.0)
        assert fp.security_upgrade_pct == 25.0

        opt = OptimizationResult(budget=50000.0, allocated_spend=45000.0, security_upgrade_pct=34.2)
        assert opt.security_upgrade_pct == 34.2


class TestRosiMetricsFormulasAndInvariants:
    """Verify mathematical bounds and safety guards of new rosi.py functions."""

    def test_security_upgrade_pct_bounds_and_guards(self):
        # Typical proportional case
        assert calculate_security_upgrade_pct(34_200_000.0, 100_000_000.0) == 34.2

        # 100% cap when risk_mitigated >= baseline
        assert calculate_security_upgrade_pct(120_000_000.0, 100_000_000.0) == 100.0
        assert calculate_security_upgrade_pct(100_000_000.0, 100_000_000.0) == 100.0

        # Zero-division & negative safeguards
        assert calculate_security_upgrade_pct(50_000.0, 0.0) == 0.0
        assert calculate_security_upgrade_pct(50_000.0, -100_000.0) == 0.0
        assert calculate_security_upgrade_pct(0.0, 100_000.0) == 0.0
        assert calculate_security_upgrade_pct(-50_000.0, 100_000.0) == 0.0

        # NaN and Inf handling
        assert calculate_security_upgrade_pct(float("nan"), 100_000.0) == 0.0
        assert calculate_security_upgrade_pct(50_000.0, float("nan")) == 0.0
        assert calculate_security_upgrade_pct(float("inf"), 100_000.0) == 0.0
        assert calculate_security_upgrade_pct(50_000.0, float("inf")) == 0.0

    def test_net_capital_saved_non_negativity(self):
        # Normal positive savings
        assert calculate_net_capital_saved(48_200_000.0, 14_000_000.0) == 34_200_000.0

        # Equal values yield 0.0
        assert calculate_net_capital_saved(48_200_000.0, 48_200_000.0) == 0.0

        # Attack surge where residual EAL > baseline EAL must clamp to 0.0
        assert calculate_net_capital_saved(48_200_000.0, 82_400_000.0) == 0.0

        # NaN and Inf safety
        assert calculate_net_capital_saved(float("nan"), 10_000.0) == 0.0
        assert calculate_net_capital_saved(10_000.0, float("nan")) == 0.0
        assert calculate_net_capital_saved(float("inf"), 10_000.0) == 0.0

    def test_security_posture_score_calibration(self):
        # Baseline unmitigated with 1 control: exactly 42.5
        score_base = calculate_security_posture_score(
            baseline_eal=48_200_000.0, current_eal=48_200_000.0, control_count=1
        )
        assert score_base == 42.5

        # Unmitigated with 0 controls: 40.0
        assert calculate_security_posture_score(48_200_000.0, 48_200_000.0, 0) == 40.0

        # High mitigation (80%) with 6 controls: ~91.0
        score_mitigated = calculate_security_posture_score(
            baseline_eal=100.0, current_eal=20.0, control_count=6
        )
        assert score_mitigated == 91.0

        # 100% mitigation with 6 controls: 100.0
        assert calculate_security_posture_score(100.0, 0.0, 6) == 100.0

        # Active attack surge (current_eal = 1.5 * baseline_eal, 1 control): 20.0
        score_attack = calculate_security_posture_score(
            baseline_eal=48_200_000.0, current_eal=72_300_000.0, control_count=1
        )
        assert score_attack == 20.0

        # Extreme attack: clamped to 0.0
        assert calculate_security_posture_score(100.0, 300.0, 0) == 0.0

        # Zero baseline guard
        assert calculate_security_posture_score(0.0, 0.0, 0) == 100.0
        assert calculate_security_posture_score(0.0, 50.0, 0) == 0.0


class TestVendorBenchmarkingAndVirtualProcurement:
    """Verify VENDOR_CATALOG completeness and apply_virtual_vendor_purchase workflow."""

    def test_vendor_catalog_contents(self):
        assert len(VENDOR_CATALOG) == 5
        assert "VND-CRWD-EDR" in VENDOR_CATALOG
        assert "VND-MSFT-SEC" in VENDOR_CATALOG
        assert "VND-CLDF-WAF" in VENDOR_CATALOG
        assert "VND-OKTA-IAM" in VENDOR_CATALOG
        assert "VND-WIZ-CSPM" in VENDOR_CATALOG

        # Check vendor categories
        categories = {v.category for v in VENDOR_CATALOG.values()}
        assert "EDR" in categories
        assert "WAF" in categories
        assert "IAM" in categories
        assert "CSPM" in categories

        # Check threat shields on each vendor
        for v in VENDOR_CATALOG.values():
            assert len(v.future_threat_shields) >= 3
            assert v.overall_coverage_rating > 85.0
            assert len(v.recommendation_tags) > 0
            assert v.annual_cost_usd > 0.0
            assert v.annual_cost_inr == v.annual_cost_usd * USD_TO_INR_RATE

        assert len(get_ceo_vendor_catalog()) == 5

    def test_get_vendor_by_id_lookup(self):
        assert get_vendor_by_id("VND-CRWD-EDR") is not None
        assert get_vendor_by_id("crowdstrike") is not None
        assert get_vendor_by_id("VND-CRWD") is not None
        assert get_vendor_by_id("cloudflare") is not None
        assert get_vendor_by_id("okta") is not None
        assert get_vendor_by_id("wiz") is not None
        assert get_vendor_by_id("microsoft") is not None
        assert get_vendor_by_id("nonexistent_vendor") is None

    def test_apply_virtual_vendor_purchase_workflow(self):
        initial_portfolio = {
            "selected_vendor_ids": [],
            "allocated_spend": 0.0,
            "baseline_eal": 48_200_000.0,
            "residual_eal": 48_200_000.0,
            "risk_mitigated": 0.0,
            "currency": "INR",
        }

        # 1. Purchase CrowdStrike Falcon
        updated = apply_virtual_vendor_purchase("VND-CRWD-EDR", initial_portfolio)
        assert updated["status"] == "PURCHASED"
        assert "VND-CRWD-EDR" in updated["selected_vendor_ids"]
        assert updated["allocated_spend"] == 12000.0 * USD_TO_INR_RATE
        assert updated["residual_eal"] < initial_portfolio["residual_eal"]
        assert updated["risk_mitigated"] > 0.0
        assert updated["security_upgrade_pct"] > 0.0
        assert updated["security_posture_score"] > 42.5

        # 2. Idempotency test (purchasing same product again)
        repurchased = apply_virtual_vendor_purchase("VND-CRWD-EDR", updated)
        assert repurchased["status"] == "ALREADY_PURCHASED"
        assert repurchased["allocated_spend"] == updated["allocated_spend"]
        assert repurchased["residual_eal"] == updated["residual_eal"]

        # 3. Add second vendor (Cloudflare WAF)
        portfolio_2 = apply_virtual_vendor_purchase("VND-CLDF-WAF", updated)
        assert len(portfolio_2["selected_vendor_ids"]) == 2
        assert portfolio_2["allocated_spend"] == (12000.0 + 14400.0) * USD_TO_INR_RATE
        assert portfolio_2["residual_eal"] < updated["residual_eal"]
        assert portfolio_2["security_upgrade_pct"] > updated["security_upgrade_pct"]
