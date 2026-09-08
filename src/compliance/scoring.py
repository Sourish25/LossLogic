"""
src/compliance/scoring.py - Quantitative Compliance Scoring and Financial Loss Attribution.
"""

from typing import Any, Dict, List, Optional, Set, Union
from src.compliance.catalog import ControlDefinition, get_framework_controls, FRAMEWORK_CATALOGS


class ComplianceScorer:
    """
    Evaluates quantitative regulatory compliance scores and attributes financial cyber risk
    exposure (EAL) to specific deficient controls.
    """

    def calculate_compliance_score(
        self,
        framework_controls: List[Union[Dict[str, Any], ControlDefinition]],
        deficient_control_ids: Set[str],
    ) -> float:
        """
        Compute weighted percentage compliance score:
        (sum(weight of passing controls) / sum(weight of all controls)) * 100.0
        """
        if not framework_controls:
            return 100.0

        total_weight = 0.0
        scored_weight = 0.0

        for c in framework_controls:
            if isinstance(c, dict):
                w = float(c.get("weight", 1.0))
                cid = str(c.get("control_id", ""))
            else:
                w = float(getattr(c, "weight", 1.0))
                cid = str(getattr(c, "control_id", ""))

            total_weight += w
            if cid not in deficient_control_ids:
                scored_weight += w

        if total_weight <= 0.0:
            return 100.0

        score = (scored_weight / total_weight) * 100.0
        return max(0.0, min(100.0, float(score)))

    def attribute_financial_exposure(
        self,
        framework_controls: List[Union[Dict[str, Any], ControlDefinition]],
        deficient_control_ids: Set[str],
        finding_risks: Dict[str, float],
        control_finding_mapping: Dict[str, List[str]],
    ) -> float:
        """
        Calculate total financial risk exposure (monetary loss in INR or USD) directly
        attributable to deficient or non-compliant controls.
        """
        impacted_findings: Set[str] = set()

        for cid in deficient_control_ids:
            for fid in control_finding_mapping.get(cid, []):
                impacted_findings.add(fid)

        attributed_loss = sum(finding_risks.get(fid, 0.0) for fid in impacted_findings)
        return max(0.0, float(attributed_loss))

    def evaluate_framework(
        self,
        framework_name: str,
        deficient_control_ids: Set[str],
        finding_risks: Optional[Dict[str, float]] = None,
        control_finding_mapping: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance assessment for a single framework."""
        controls = get_framework_controls(framework_name)
        ctrl_dicts = [c.model_dump() for c in controls]
        finding_risks = finding_risks or {}
        control_finding_mapping = control_finding_mapping or {}

        score = self.calculate_compliance_score(ctrl_dicts, deficient_control_ids)
        exposure = self.attribute_financial_exposure(
            ctrl_dicts, deficient_control_ids, finding_risks, control_finding_mapping
        )

        all_cids = [c.control_id for c in controls]
        failing_cids = [c.control_id for c in controls if c.control_id in deficient_control_ids]
        passing_cids = [c.control_id for c in controls if c.control_id not in deficient_control_ids]

        return {
            "framework": framework_name,
            "compliance_pct": round(score, 2),
            "total_controls": len(controls),
            "passing_controls": len(passing_cids),
            "failing_controls": len(failing_cids),
            "attributed_exposure": round(exposure, 2),
            "deficient_control_ids": failing_cids,
            "controls": [
                {
                    "control_id": c.control_id,
                    "section": c.section,
                    "title": c.title,
                    "weight": c.weight,
                    "status": "DEFICIENT" if c.control_id in deficient_control_ids else "COMPLIANT",
                    "attributed_findings": control_finding_mapping.get(c.control_id, []),
                }
                for c in controls
            ],
        }

    def evaluate_all_frameworks(
        self,
        deficient_control_ids: Set[str],
        finding_risks: Optional[Dict[str, float]] = None,
        control_finding_mapping: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """Evaluate compliance across all 5 standard regulatory frameworks."""
        results: Dict[str, Any] = {}
        scores: List[float] = []
        total_attributed_exposure = 0.0

        for fw in ["ISO_27001", "NIST_CSF", "CIS_V8", "RBI_CSF", "SEBI_CSCRF"]:
            fw_res = self.evaluate_framework(
                fw, deficient_control_ids, finding_risks, control_finding_mapping
            )
            results[fw] = fw_res
            scores.append(fw_res["compliance_pct"])
            total_attributed_exposure += fw_res["attributed_exposure"]

        composite_score = sum(scores) / max(1, len(scores))
        return {
            "composite_compliance_pct": round(composite_score, 2),
            "total_attributed_exposure": round(total_attributed_exposure, 2),
            "frameworks": results,
        }
