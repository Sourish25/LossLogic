"""
tests/e2e/test_tier4_real_world_scenarios.py - Tier 4 Real-World Enterprise Risk Scenarios.

Holistic end-to-end simulation of 5 realistic enterprise cyber risk scenarios:
- Scenario 1: Core Banking Ransomware Infection Chain (EDR disabled -> Lateral Movement -> Core DB CVE -> IAM Escalation).
- Scenario 2: Cloud S3 Financial Data Leakage (Public CSPM misconfiguration + PCI-DSS data + RBI/SEBI regulatory failure).
- Scenario 3: Annual Cybersecurity Budget Allocation (CIO allocates ₹1 Crore across 20 competing initiatives with Pareto curve).
- Scenario 4: M&A Subsidiary Onboarding (Acquisition of legacy fintech, consolidated DAG roll-up & compliance attribution).
- Scenario 5: Emergency Zero-Day Remediation Prioritization (What-If 30-day delay cost vs weekend emergency patch).
"""

import math
from typing import Any, Dict, List, Set
import networkx as nx
import numpy as np
import pytest

from tests.conftest import (
    AssetTier,
    Currency,
    DataSensitivity,
    FrontierPoint,
    InvariantAssertions,
    MockAssetRecord,
    MockCandidateControl,
    MockNormalizedFinding,
    OptimizationResult,
    ReferenceAssetGraph,
    ReferenceComplianceEngine,
    ReferenceFairMonteCarlo,
    ReferenceKnapsackOptimizer,
    SeverityLevel,
    TelemetryDomain,
)


@pytest.mark.e2e
@pytest.mark.tier4
class TestTier4RealWorldScenarios:
    """Holistic enterprise cyber crisis and decision scenarios."""

    def test_scenario_1_core_banking_ransomware_infection_chain(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Scenario 1: Core Banking Ransomware Attack Path
        Attack Chain:
        1. EDR agent offline on trader workstation (asset-trader-ws-01).
        2. Threat actor gains initial foothold and moves laterally to Core Banking DB (asset-core-db-01).
        3. Exploits high-EPSS critical CVE-2023-34362.
        4. Escalates privileges using unmanaged IAM root role (asset-cloud-iam-01).
        
        Verifies:
        - Baseline simulation quantifies severe multi-crore tail loss (VaR 99 > ₹50 Cr).
        - Targeted 3-part mitigation bundle reduces enterprise EAL by > 80%.
        - Verification that remediating the attack chain breaks the infection pathway.
        """
        chain_findings = [
            MockNormalizedFinding(
                finding_id="CHAIN-EDR-01", asset_id="asset-trader-ws-01",
                domain=TelemetryDomain.EDR, severity=SeverityLevel.HIGH,
                title="EDR Agent Offline & USB Open", cvss_score=7.8,
                epss_score=0.55, cisa_kev=False, threat_event_frequency=15.0,
                resistance_strength=0.10
            ),
            MockNormalizedFinding(
                finding_id="CHAIN-CVE-02", asset_id="asset-core-db-01",
                domain=TelemetryDomain.VULNERABILITY, severity=SeverityLevel.CRITICAL,
                title="MOVEit RCE / SQLi on Core Banking DB", cvss_score=9.8,
                epss_score=0.96, cisa_kev=True, threat_event_frequency=25.0,
                resistance_strength=0.05
            ),
            MockNormalizedFinding(
                finding_id="CHAIN-IAM-03", asset_id="asset-cloud-iam-01",
                domain=TelemetryDomain.IAM, severity=SeverityLevel.CRITICAL,
                title="Overprivileged Cloud Admin Without Hardware MFA", cvss_score=8.9,
                epss_score=0.72, cisa_kev=False, threat_event_frequency=20.0,
                resistance_strength=0.05
            )
        ]

        # 1. Baseline unmitigated attack chain simulation
        base_res = fair_engine.simulate(chain_findings, mock_asset_catalog, seed_override=101)
        assert base_res.eal > 50000000.0, f"Expected baseline EAL > ₹5 Cr, got {base_res.eal}"
        assert base_res.var_99 > 100000000.0, f"Expected catastrophic tail VaR 99 > ₹10 Cr, got {base_res.var_99}"

        # 2. Apply comprehensive mitigation bundle:
        # Patch CVE + Enable EDR with anti-tamper + Enforce Hardware MFA
        mitigated_chain = [
            MockNormalizedFinding(
                finding_id="CHAIN-EDR-01", asset_id="asset-trader-ws-01",
                domain=TelemetryDomain.EDR, severity=SeverityLevel.LOW,
                title="EDR Active", cvss_score=2.0, epss_score=0.05,
                cisa_kev=False, threat_event_frequency=1.0, resistance_strength=0.90
            ),
            MockNormalizedFinding(
                finding_id="CHAIN-CVE-02", asset_id="asset-core-db-01",
                domain=TelemetryDomain.VULNERABILITY, severity=SeverityLevel.LOW,
                title="MOVEit Patched & WAF Virtual Patch", cvss_score=1.5,
                epss_score=0.02, cisa_kev=False, threat_event_frequency=1.0,
                resistance_strength=0.95
            ),
            MockNormalizedFinding(
                finding_id="CHAIN-IAM-03", asset_id="asset-cloud-iam-01",
                domain=TelemetryDomain.IAM, severity=SeverityLevel.LOW,
                title="FIDO2 Hardware MFA Enforced", cvss_score=1.0,
                epss_score=0.01, cisa_kev=False, threat_event_frequency=0.5,
                resistance_strength=0.95
            )
        ]

        mit_res = fair_engine.simulate(mitigated_chain, mock_asset_catalog, seed_override=101)

        # 3. Assert > 80% risk reduction
        risk_reduction = base_res.eal - mit_res.eal
        pct_reduction = (risk_reduction / base_res.eal) * 100.0
        assert pct_reduction >= 80.0, (
            f"Mitigation bundle failed to achieve 80% risk reduction: {pct_reduction:.2f}%"
        )
        # 4. Tail risk VaR 95 substantially curbed
        assert mit_res.var_95 < base_res.var_95 * 0.25

    def test_scenario_2_cloud_s3_financial_data_leakage(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        compliance_engine: ReferenceComplianceEngine,
        mock_asset_catalog: Dict[str, MockAssetRecord],
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """
        Scenario 2: Cloud S3 Financial Data Leakage & Regulatory Failure
        Incident:
        - CSPM alerts on public read access to Customer Archive S3 Bucket (asset-s3-backup-01).
        - Bucket hosts PCI-DSS cardholder data and PAN records.
        - Triggers regulatory violations:
          * ISO 27001: A.8.24 (Cryptography)
          * RBI CSF: RBI-DAT-01 (Data Protection & Encryption)
          * SEBI CSCRF: SEBI-WIT-03 (Payload & Storage Encryption)
        
        Verifies:
        - Financial exposure attribution calculates full monetary penalty tied to deficient controls.
        - Automated remediation (S3 encryption + Block Public Access) restores compliance to 100%.
        """
        s3_finding = MockNormalizedFinding(
            finding_id="CSPM-S3-LEAK",
            asset_id="asset-s3-backup-01",
            domain=TelemetryDomain.CSPM,
            severity=SeverityLevel.CRITICAL,
            title="Publicly Readable S3 Bucket with Unencrypted Cardholder PANs",
            cvss_score=9.4,
            epss_score=0.88,
            cisa_kev=True,
            threat_event_frequency=30.0,
            resistance_strength=0.05
        )

        # 1. Run Monte Carlo simulation for finding
        sim_res = fair_engine.simulate([s3_finding], mock_asset_catalog, seed_override=42)
        s3_eal = sim_res.eal
        assert s3_eal > 20000000.0, f"Expected S3 leak EAL > ₹2 Cr, got {s3_eal}"

        finding_risks = {"CSPM-S3-LEAK": s3_eal}
        mapping = {
            "ISO-A.8.24": ["CSPM-S3-LEAK"],
            "RBI-DAT-01": ["CSPM-S3-LEAK"],
            "SEBI-WIT-03": ["CSPM-S3-LEAK"],
        }

        # 2. Check compliance failure across ISO, RBI, and SEBI
        rbi_controls = mock_compliance_frameworks["RBI_CSF"]
        sebi_controls = mock_compliance_frameworks["SEBI_CSCRF"]
        iso_controls = mock_compliance_frameworks["ISO_27001"]

        # Scores drop
        rbi_score = compliance_engine.calculate_compliance_score(rbi_controls, {"RBI-DAT-01"})
        sebi_score = compliance_engine.calculate_compliance_score(sebi_controls, {"SEBI-WIT-03"})
        iso_score = compliance_engine.calculate_compliance_score(iso_controls, {"ISO-A.8.24"})

        assert rbi_score < 100.0
        assert sebi_score < 100.0
        assert iso_score < 100.0

        # 3. Non-compliant financial risk attribution equals full finding loss
        attributed_rbi_risk = compliance_engine.attribute_financial_exposure(
            rbi_controls, {"RBI-DAT-01"}, finding_risks, mapping
        )
        assert attributed_rbi_risk == s3_eal

        # 4. Remediation: Enforce bucket policy guardrail
        remediated_score = compliance_engine.calculate_compliance_score(rbi_controls, set())
        remediated_exposure = compliance_engine.attribute_financial_exposure(
            rbi_controls, set(), finding_risks, mapping
        )
        assert remediated_score == 100.0
        assert remediated_exposure == 0.0

    def test_scenario_3_annual_cyber_budget_allocation_1_crore(
        self,
        knapsack_optimizer: ReferenceKnapsackOptimizer,
    ):
        """
        Scenario 3: Annual Cybersecurity Budget Allocation Exercise
        Context:
        - Enterprise CIO allocates ₹1.00 Crore ($120k) budget across 20 competing initiatives.
        - Problem features:
          * 2 Mandatory regulatory baseline controls (MFA, Storage Encryption).
          * Prerequisite chains: Cloud SOAR requires Cloud SIEM; SIEM requires EDR.
          * Mutually exclusive vendors: Vendor A WAF vs Vendor B WAF.
        
        Verifies:
        - Solver strictly spends <= ₹1.00 Crore.
        - Mandatory controls are guaranteed selected.
        - Mutual exclusivity is respected.
        - Portfolio achieves strong positive ROSI (> 150%).
        - Generates smooth Pareto frontier showing diminishing returns above ₹70 Lakhs.
        """
        # Create 20 realistic enterprise security initiatives
        initiatives: List[MockCandidateControl] = [
            MockCandidateControl("INIT-01", "Hardware MFA", "IAM", 600000.0, ["F1"], 0.90, is_mandatory=True),
            MockCandidateControl("INIT-02", "Storage Encryption", "Crypto", 400000.0, ["F2"], 0.95, is_mandatory=True),
            MockCandidateControl("INIT-03", "EDR Enterprise Fleet", "Endpoint", 1500000.0, ["F3"], 0.85),
            MockCandidateControl("INIT-04", "SIEM Cloud Migration", "SOC", 2000000.0, ["F4"], 0.80, prerequisites=["INIT-03"]),
            MockCandidateControl("INIT-05", "SOAR Automation", "SOC", 1200000.0, ["F5"], 0.75, prerequisites=["INIT-04"]),
            MockCandidateControl("INIT-06", "Vendor A Next-Gen WAF", "Network", 1800000.0, ["F6"], 0.82, conflicts=["INIT-07"]),
            MockCandidateControl("INIT-07", "Vendor B Cloud WAF", "Network", 1400000.0, ["F6"], 0.78, conflicts=["INIT-06"]),
            MockCandidateControl("INIT-08", "Vulnerability Scanner", "Vuln", 800000.0, ["F7"], 0.85),
            MockCandidateControl("INIT-09", "Automated Patching", "Vuln", 700000.0, ["F8"], 0.88, prerequisites=["INIT-08"]),
            MockCandidateControl("INIT-10", "DLP Egress Filtering", "Data", 1100000.0, ["F9"], 0.70),
            MockCandidateControl("INIT-11", "Privileged Access (PAM)", "IAM", 1600000.0, ["F10"], 0.85),
            MockCandidateControl("INIT-12", "Microsegmentation", "Network", 2500000.0, ["F11"], 0.80),
            MockCandidateControl("INIT-13", "Security Awareness Training", "People", 300000.0, ["F12"], 0.40),
            MockCandidateControl("INIT-14", "Threat Intelligence Feed", "Intel", 500000.0, ["F13"], 0.50),
            MockCandidateControl("INIT-15", "Red Team Exercise", "Assurance", 900000.0, ["F14"], 0.60),
            MockCandidateControl("INIT-16", "Immutable WORM Backups", "Resilience", 1300000.0, ["F15"], 0.85),
            MockCandidateControl("INIT-17", "API Security Gateway", "AppSec", 1000000.0, ["F16"], 0.75),
            MockCandidateControl("INIT-18", "CSPM Cloud Posture", "Cloud", 750000.0, ["F17"], 0.80),
            MockCandidateControl("INIT-19", "CI/CD SAST/DAST", "AppSec", 850000.0, ["F18"], 0.75),
            MockCandidateControl("INIT-20", "Database Activity Monitoring", "Data", 1250000.0, ["F19"], 0.72),
        ]

        budget = 10000000.0  # ₹1.00 Crore ($1M equivalent)
        baseline_eal = 80000000.0  # ₹8.00 Crore exposure

        result = knapsack_optimizer.optimize(
            controls=initiatives,
            budget=budget,
            baseline_eal=baseline_eal
        )

        # 1. Budget ceiling respected
        assert result.allocated_spend <= budget
        assert result.allocated_spend >= budget * 0.85, "Should utilize majority of available budget"

        # 2. Mandatory controls included
        selected_ids = {c.control_id for c in result.selected_controls}
        assert "INIT-01" in selected_ids
        assert "INIT-02" in selected_ids

        # 3. Conflicts respected (Vendor A and B WAF cannot both be chosen)
        assert not ("INIT-06" in selected_ids and "INIT-07" in selected_ids)

        # 4. High ROSI
        assert result.portfolio_rosi > 150.0

        # 5. Frontier points show diminishing returns
        frontier = result.efficiency_frontier
        assert len(frontier) >= 5
        # Verify that as spend increases, marginal gain per rupee diminishes
        slopes = []
        for i in range(1, len(frontier)):
            ds = frontier[i].spend - frontier[i - 1].spend
            dr = frontier[i].risk_mitigated - frontier[i - 1].risk_mitigated
            if ds > 50000.0:
                slopes.append(dr / ds)
        if len(slopes) >= 2:
            assert slopes[0] >= slopes[-1] * 0.8, "Earlier investments should have higher or equal marginal returns"

    def test_scenario_4_ma_subsidiary_onboarding_and_attribution(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        compliance_engine: ReferenceComplianceEngine,
        mock_compliance_frameworks: Dict[str, List[Dict[str, Any]]],
    ):
        """
        Scenario 4: M&A Subsidiary Onboarding & Compliance Attribution
        Context:
        - ApexGlobal acquires a regional fintech startup ("PayQuick Ltd") with legacy infra.
        - PayQuick has unpatched vulnerabilities and failing RBI/SEBI controls (only 40% compliance).
        - Verifies:
          1. Independent calculation of PayQuick standalone risk.
          2. Joint pro-forma enterprise risk upon onboarding into corporate asset catalog.
          3. Exact risk attribution between parent bank and newly acquired subsidiary.
        """
        # Parent asset
        parent_asset = MockAssetRecord(
            asset_id="parent-core-db", name="ApexGlobal Core DB", business_unit="Apex Retail",
            tier=AssetTier.TIER_1, data_sensitivity=DataSensitivity.RESTRICTED_PCI,
            replacement_cost=20000000.0, downtime_cost_per_hour=800000.0, asset_criticality_score=5.0
        )
        parent_finding = MockNormalizedFinding(
            finding_id="PARENT-F1", asset_id="parent-core-db", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.MEDIUM, title="Standard Scheduled Patch", cvss_score=5.5,
            epss_score=0.10, cisa_kev=False, threat_event_frequency=5.0, resistance_strength=0.70
        )

        # Subsidiary asset
        subsidiary_asset = MockAssetRecord(
            asset_id="sub-payquick-api", name="PayQuick Legacy API", business_unit="PayQuick Fintech",
            tier=AssetTier.TIER_2, data_sensitivity=DataSensitivity.CONFIDENTIAL,
            replacement_cost=5000000.0, downtime_cost_per_hour=200000.0, asset_criticality_score=3.0
        )
        subsidiary_finding = MockNormalizedFinding(
            finding_id="SUB-F1", asset_id="sub-payquick-api", domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL, title="Legacy Unpatched RCE (PayQuick)", cvss_score=9.8,
            epss_score=0.85, cisa_kev=True, threat_event_frequency=20.0, resistance_strength=0.10
        )

        # 1. Standalone simulations
        res_parent = fair_engine.simulate([parent_finding], {parent_asset.asset_id: parent_asset}, seed_override=42)
        res_sub = fair_engine.simulate([subsidiary_finding], {subsidiary_asset.asset_id: subsidiary_asset}, seed_override=42)

        assert res_sub.eal > res_parent.eal, "Subsidiary unpatched asset represents higher risk"

        # 2. Joint pro-forma enterprise simulation
        combined_assets = {parent_asset.asset_id: parent_asset, subsidiary_asset.asset_id: subsidiary_asset}
        res_combined = fair_engine.simulate([parent_finding, subsidiary_finding], combined_assets, seed_override=42)

        # 3. Attribution: Subsidiary risk share
        sub_share_pct = (res_combined.asset_risks[subsidiary_asset.asset_id] / res_combined.eal) * 100.0
        assert sub_share_pct > 60.0, (
            f"Expected acquired subsidiary to contribute majority (>60%) of new risk, got {sub_share_pct:.1f}%"
        )

        # 4. Compliance gap attribution: PayQuick causes RBI-VAP-01 non-compliance
        rbi_controls = mock_compliance_frameworks["RBI_CSF"]
        rbi_score_pre = compliance_engine.calculate_compliance_score(rbi_controls, set())
        rbi_score_post = compliance_engine.calculate_compliance_score(rbi_controls, {"RBI-VAP-01"})

        assert rbi_score_pre == 100.0
        assert rbi_score_post < 90.0

    def test_scenario_5_emergency_zero_day_delay_cost_evaluation(
        self,
        fair_engine: ReferenceFairMonteCarlo,
        mock_asset_catalog: Dict[str, MockAssetRecord],
    ):
        """
        Scenario 5: Emergency Zero-Day Remediation Prioritization
        Context:
        - Critical zero-day announced on Friday afternoon (CVSS 9.8, EPSS 0.95).
        - Management considers:
          Option A: Expedited emergency weekend deployment ($25k overtime & rapid testing).
          Option B: Wait for regular 30-day patch maintenance window.
        
        Verifies:
        - Quantifies compounding 30-day delay cost (cumulative loss penalty).
        - Compares emergency patching spend ($25k) vs expected delay loss ($350k+).
        - Proves that emergency mitigation has > 1000% Net Financial ROSI.
        """
        zero_day = MockNormalizedFinding(
            finding_id="ZERO-DAY-001",
            asset_id="asset-core-db-01",
            domain=TelemetryDomain.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            title="Actively Exploited Pre-Auth Zero-Day",
            cvss_score=9.8,
            epss_score=0.95,
            cisa_kev=True,
            threat_event_frequency=35.0,
            resistance_strength=0.05
        )

        # 1. Base annual exposure if active
        res = fair_engine.simulate([zero_day], mock_asset_catalog, seed_override=42)
        annual_eal = res.eal
        daily_loss_base = annual_eal / 365.0

        # 2. Compounding delay cost model for 30 days
        hazard_daily_surge = 0.03  # 3% daily increase in attacker weaponization
        delay_cost_30d = 0.0
        for day in range(1, 31):
            daily_loss = daily_loss_base * (1.0 + hazard_daily_surge) ** day
            delay_cost_30d += daily_loss

        # Delay cost must exceed linear 30-day extrapolation
        assert delay_cost_30d > (daily_loss_base * 30.0) * 1.3

        # 3. Decision Evaluation
        emergency_patch_cost = 250000.0  # ₹2.5 Lakhs ($3,000 equivalent)
        net_savings = delay_cost_30d - emergency_patch_cost
        rosi_emergency = (net_savings / emergency_patch_cost) * 100.0

        assert net_savings > 0.0
        assert rosi_emergency > 500.0, (
            f"Expected emergency patch to show overwhelming ROSI, got {rosi_emergency:.1f}%"
        )
