"""
tests/unit/test_compliance.py - Comprehensive Unit Tests for Regulatory Compliance Engine.
"""

import pytest
from src.compliance.catalog import (
    get_framework_controls,
    get_framework_controls_as_dicts,
    get_all_frameworks,
    FRAMEWORK_CATALOGS,
    ControlDefinition,
)
from src.compliance.mapper import ComplianceMapper
from src.compliance.scoring import ComplianceScorer


@pytest.fixture
def scorer() -> ComplianceScorer:
    return ComplianceScorer()


class TestComplianceCatalog:
    """Validates regulatory framework catalog completeness and integrity."""

    @pytest.mark.parametrize("fw_name", ["ISO_27001", "NIST_CSF", "CIS_V8", "RBI_CSF", "SEBI_CSCRF"])
    def test_framework_controls_non_empty(self, fw_name: str):
        controls = get_framework_controls(fw_name)
        assert len(controls) >= 5, f"Framework {fw_name} must have at least 5 controls"
        for c in controls:
            assert isinstance(c, ControlDefinition)
            assert c.control_id
            assert c.title
            assert c.section
            assert c.weight > 0.0

    def test_nist_csf_functions_represented(self):
        controls = get_framework_controls("NIST_CSF")
        sections = {c.section for c in controls}
        assert "Protect" in sections
        assert "Detect" in sections
        mfa_ctrl = [c for c in controls if c.control_id == "PR.AA-05"][0]
        assert mfa_ctrl.weight == 3.0

    def test_rbi_specific_controls(self):
        controls = get_framework_controls("RBI_CSF")
        cids = {c.control_id for c in controls}
        assert "RBI-IAM-01" in cids
        assert "RBI-VAP-01" in cids
        assert "RBI-SOC-01" in cids
        assert "RBI-DAT-01" in cids

    def test_sebi_specific_pillars(self):
        controls = get_framework_controls("SEBI_CSCRF")
        sections = {c.section for c in controls}
        assert "Withstand" in sections
        assert "Contain" in sections
        cids = {c.control_id for c in controls}
        assert "SEBI-WIT-01" in cids
        assert "SEBI-CON-02" in cids
        assert "SEBI-CON-03" in cids

    def test_get_all_frameworks(self):
        all_fws = get_all_frameworks()
        assert len(all_fws) == 5
        assert "ISO_27001" in all_fws
        assert "SEBI_CSCRF" in all_fws


class TestComplianceScoring:
    """Validates quantitative compliance calculation invariants."""

    def test_perfect_compliance_score(self, scorer: ComplianceScorer):
        iso_ctrls = get_framework_controls_as_dicts("ISO_27001")
        score = scorer.calculate_compliance_score(iso_ctrls, set())
        assert score == 100.0

    def test_single_deficiency_decreases_score(self, scorer: ComplianceScorer):
        iso_ctrls = get_framework_controls_as_dicts("ISO_27001")
        score_full = scorer.calculate_compliance_score(iso_ctrls, set())
        score_def = scorer.calculate_compliance_score(iso_ctrls, {"ISO-A.8.8"})
        assert score_def < score_full
        assert 0.0 <= score_def <= 100.0

    def test_multiple_deficiencies_monotonically_decrease_score(self, scorer: ComplianceScorer):
        iso_ctrls = get_framework_controls_as_dicts("ISO_27001")
        score_1 = scorer.calculate_compliance_score(iso_ctrls, {"ISO-A.8.8"})
        score_2 = scorer.calculate_compliance_score(iso_ctrls, {"ISO-A.8.8", "ISO-A.8.2"})
        assert score_2 < score_1
        assert score_2 >= 0.0

    def test_all_deficiencies_yields_zero_score(self, scorer: ComplianceScorer):
        iso_ctrls = get_framework_controls_as_dicts("ISO_27001")
        all_cids = {c["control_id"] for c in iso_ctrls}
        score_zero = scorer.calculate_compliance_score(iso_ctrls, all_cids)
        assert score_zero == 0.0

    def test_empty_controls_returns_100(self, scorer: ComplianceScorer):
        assert scorer.calculate_compliance_score([], {"SOME-ID"}) == 100.0


class TestFinancialExposureAttribution:
    """Validates attribution of quantitative losses to deficient controls."""

    def test_zero_exposure_when_compliant(self, scorer: ComplianceScorer):
        rbi_ctrls = get_framework_controls_as_dicts("RBI_CSF")
        finding_risks = {"VULN-001": 18500000.0, "IAM-001": 11000000.0}
        mapping = {"RBI-VAP-01": ["VULN-001"], "RBI-IAM-01": ["IAM-001"]}

        exposure = scorer.attribute_financial_exposure(
            rbi_ctrls, set(), finding_risks, mapping
        )
        assert exposure == 0.0

    def test_single_deficient_control_exposure(self, scorer: ComplianceScorer):
        rbi_ctrls = get_framework_controls_as_dicts("RBI_CSF")
        finding_risks = {"VULN-001": 18500000.0, "IAM-001": 11000000.0}
        mapping = {"RBI-VAP-01": ["VULN-001"], "RBI-IAM-01": ["IAM-001"]}

        exposure = scorer.attribute_financial_exposure(
            rbi_ctrls, {"RBI-VAP-01"}, finding_risks, mapping
        )
        assert exposure == 18500000.0

    def test_both_deficient_controls_exposure(self, scorer: ComplianceScorer):
        rbi_ctrls = get_framework_controls_as_dicts("RBI_CSF")
        finding_risks = {"VULN-001": 18500000.0, "IAM-001": 11000000.0}
        mapping = {"RBI-VAP-01": ["VULN-001"], "RBI-IAM-01": ["IAM-001"]}

        exposure = scorer.attribute_financial_exposure(
            rbi_ctrls, {"RBI-VAP-01", "RBI-IAM-01"}, finding_risks, mapping
        )
        assert exposure == 29500000.0

    def test_unmapped_control_yields_zero_exposure(self, scorer: ComplianceScorer):
        rbi_ctrls = get_framework_controls_as_dicts("RBI_CSF")
        finding_risks = {"VULN-001": 18500000.0}
        mapping = {"RBI-VAP-01": ["VULN-001"]}

        exposure = scorer.attribute_financial_exposure(
            rbi_ctrls, {"RBI-DAT-01"}, finding_risks, mapping
        )
        assert exposure == 0.0


class TestComplianceMapper:
    """Validates bidirectional finding-to-control mapping."""

    def test_explicit_findings_mapping(self):
        controls = ComplianceMapper.get_controls_for_finding({"finding_id": "VULN-001"})
        assert "ISO-A.8.8" in controls
        assert "RBI-VAP-01" in controls

    def test_build_control_to_findings_mapping(self):
        findings = [
            {"finding_id": "VULN-001"},
            {"finding_id": "IAM-001"},
        ]
        mapping = ComplianceMapper.build_control_to_findings_mapping(findings)
        assert "ISO-A.8.8" in mapping
        assert "VULN-001" in mapping["ISO-A.8.8"]
        assert "RBI-IAM-01" in mapping
        assert "IAM-001" in mapping["RBI-IAM-01"]

    def test_evaluate_all_frameworks_matrix(self, scorer: ComplianceScorer):
        finding_risks = {"VULN-001": 15000000.0}
        mapping = {"ISO-A.8.8": ["VULN-001"], "RBI-VAP-01": ["VULN-001"]}
        deficient = {"ISO-A.8.8", "RBI-VAP-01"}

        matrix = scorer.evaluate_all_frameworks(deficient, finding_risks, mapping)
        assert "composite_compliance_pct" in matrix
        assert 0.0 <= matrix["composite_compliance_pct"] <= 100.0
        assert "ISO_27001" in matrix["frameworks"]
        assert "RBI_CSF" in matrix["frameworks"]
        assert matrix["frameworks"]["ISO_27001"]["compliance_pct"] < 100.0
        assert matrix["frameworks"]["NIST_CSF"]["compliance_pct"] == 100.0
