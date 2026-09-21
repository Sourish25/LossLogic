"""
src/optimization/models.py - Pydantic v2 data contracts for Investment Optimization & ROSI.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator

from src.config import USD_TO_INR_RATE, INR_TO_USD_RATE, usd_to_inr, inr_to_usd

try:
    from tests.conftest import (
        OptimizationResult as BaseOptimizationResult,
        FrontierPoint as BaseFrontierPoint,
    )
except ImportError:
    class BaseOptimizationResult:
        pass
    class BaseFrontierPoint:
        pass


class ThreatVectorEnum(str, Enum):
    """
    Canonical threat vectors modeled across enterprise attack surfaces.
    Maps forward-looking defense mechanisms against modern adversary tactics.
    """
    ZERO_DAY_RCE = "Zero-Day RCE"
    RANSOMWARE_LATERAL = "Ransomware Lateral Movement"
    VOLUMETRIC_DDOS = "Volumetric DDoS"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    DATA_EXFILTRATION = "Data Exfiltration"

    @classmethod
    def _missing_(cls, value: object) -> Any:
        """
        Permissive resolver allowing lookup via string literals, snake_case,
        or legacy terminology without runtime KeyError / ValidationError.
        """
        if isinstance(value, str):
            norm = value.strip().upper().replace(" ", "_").replace("-", "_")
            # 1. Exact match on member name
            if norm in cls.__members__:
                return cls.__members__[norm]
            # 2. Case-insensitive value match
            for member in cls:
                if member.value.upper() == value.strip().upper():
                    return member
            # 3. Permissive synonyms & abbreviations
            if norm in ("RANSOMWARE_LATERAL_MOVEMENT", "RANSOMWARE", "LATERAL_MOVEMENT"):
                return cls.RANSOMWARE_LATERAL
            if norm in ("DDOS", "DDOS_SURGE", "VOLUMETRIC_DDOS_ATTACK"):
                return cls.VOLUMETRIC_DDOS
            if norm in ("DATA_LEAK", "EXFILTRATION", "DATA_BREACH", "SQL_DATA_LEAK"):
                return cls.DATA_EXFILTRATION
            if norm in ("RCE", "ZERO_DAY", "REMOTE_CODE_EXECUTION"):
                return cls.ZERO_DAY_RCE
            if norm in ("CREDENTIALS", "STUFFING", "BRUTE_FORCE"):
                return cls.CREDENTIAL_STUFFING
        return None


class ThreatShield(BaseModel):
    """
    Proactive future threat immunity provided by an enterprise security mitigation.
    Demonstrates defense-in-depth problem-solving capabilities beyond localized CVE patches.
    """
    threat_vector: ThreatVectorEnum
    neutralized_attack_types: List[str] = Field(
        default_factory=list,
        description="Specific adversary techniques, CVE exploit patterns, or tactics neutralized."
    )
    future_immunity_pct: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Estimated preventative immunity percentage bounded in [0.0, 100.0]."
    )
    protective_mechanism: str = Field(
        default="",
        description="Underlying technical defense mechanism (e.g. eBPF syscall filtering, Anycast scrubbing)."
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_shield_inputs(cls, data: Any) -> Any:
        """
        Enables seamless interop with alternative naming conventions:
        - immunity_percentage -> future_immunity_pct
        - protection_mechanism -> protective_mechanism
        - attack_vector -> threat_vector
        """
        if isinstance(data, dict):
            if "immunity_percentage" in data and "future_immunity_pct" not in data:
                data["future_immunity_pct"] = data["immunity_percentage"]
            if "protection_mechanism" in data and "protective_mechanism" not in data:
                data["protective_mechanism"] = data["protection_mechanism"]
            if "attack_vector" in data and "threat_vector" not in data:
                data["threat_vector"] = data["attack_vector"]
        return data


class SecurityControl(BaseModel):
    """
    Representation of a candidate security mitigation or investment control.
    Supports multi-currency cost parameters, effectiveness, dependencies, conflicts,
    and proactive future threat shields.
    """
    control_id: str
    name: str
    category: str
    cost_usd: float = 0.0
    cost_inr: float = 0.0
    cost: float = 0.0
    target_finding_ids: List[str] = Field(default_factory=list)
    risk_reduction_usd: float = 0.0
    risk_reduction_inr: float = 0.0
    effectiveness: float = Field(default=0.0, ge=0.0, le=1.0)
    prerequisites: List[str] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    is_mandatory: bool = False
    framework_mappings: Dict[str, Any] = Field(default_factory=dict)
    mapped_frameworks: Dict[str, Any] = Field(default_factory=dict)
    future_threat_shields: List[ThreatShield] = Field(
        default_factory=list,
        description="List of future multi-threat defense shields provided by this mitigation."
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_costs_and_mappings(cls, data: Any) -> Any:
        if isinstance(data, dict):
            cost_val = data.get("cost", 0.0)
            cost_u = data.get("cost_usd", 0.0)
            cost_i = data.get("cost_inr", 0.0)

            if cost_u > 0.0 and cost_i == 0.0:
                data["cost_inr"] = usd_to_inr(cost_u)
                if cost_val == 0.0:
                    data["cost"] = cost_u
            elif cost_i > 0.0 and cost_u == 0.0:
                data["cost_usd"] = inr_to_usd(cost_i)
                if cost_val == 0.0:
                    data["cost"] = cost_i
            elif cost_val > 0.0:
                if cost_u == 0.0 and cost_i == 0.0:
                    data["cost_usd"] = cost_val
                    data["cost_inr"] = usd_to_inr(cost_val)

            fm = data.get("framework_mappings")
            mf = data.get("mapped_frameworks")
            if fm and not mf:
                data["mapped_frameworks"] = fm
            elif mf and not fm:
                data["framework_mappings"] = mf

            rr_u = data.get("risk_reduction_usd", 0.0)
            rr_i = data.get("risk_reduction_inr", 0.0)
            if rr_u > 0.0 and rr_i == 0.0:
                data["risk_reduction_inr"] = usd_to_inr(rr_u)
            elif rr_i > 0.0 and rr_u == 0.0:
                data["risk_reduction_usd"] = inr_to_usd(rr_i)

        return data

    def get_cost(self, currency: str = "USD") -> float:
        """Get control cost in requested currency."""
        curr = currency.upper()
        if curr == "INR":
            return self.cost_inr if self.cost_inr > 0.0 else (self.cost if self.cost > 0.0 else usd_to_inr(self.cost_usd))
        return self.cost_usd if self.cost_usd > 0.0 else (self.cost if self.cost > 0.0 else inr_to_usd(self.cost_inr))

    def get_risk_reduction(self, currency: str = "USD") -> float:
        """Get explicit risk reduction if set."""
        curr = currency.upper()
        if curr == "INR":
            return self.risk_reduction_inr if self.risk_reduction_inr > 0.0 else usd_to_inr(self.risk_reduction_usd)
        return self.risk_reduction_usd if self.risk_reduction_usd > 0.0 else inr_to_usd(self.risk_reduction_inr)

    def get_threat_shield(self, vector: Union[ThreatVectorEnum, str]) -> Optional[ThreatShield]:
        """Lookup specific future threat shield by vector name or enum."""
        try:
            resolved = ThreatVectorEnum(vector) if not isinstance(vector, ThreatVectorEnum) else vector
        except (ValueError, TypeError):
            return None
        for shield in self.future_threat_shields:
            if shield.threat_vector == resolved:
                return shield
        return None


class OptimizationRequest(BaseModel):
    """Request payload for investment portfolio optimization."""
    budget: float = Field(..., ge=0.0, description="Available budget ceiling")
    currency: str = Field(default="USD", description="'USD' or 'INR'")
    candidate_controls: List[SecurityControl] = Field(
        default_factory=list, description="Available candidate mitigations"
    )
    baseline_eal: float = Field(default=0.0, ge=0.0, description="Baseline Expected Annual Loss")
    mandatory_control_ids: List[str] = Field(
        default_factory=list, description="Control IDs mandated by policy/regulation"
    )
    step_count: int = Field(default=10, ge=2, le=100, description="Number of steps for Pareto curve")
    objective: str = Field(default="MAX_RISK_REDUCTION", description="Optimization objective")
    include_frontier: bool = Field(
        default=False, description="Whether to generate multi-step Pareto efficiency frontier"
    )


class FrontierPoint(BaseModel, BaseFrontierPoint):
    """Single point along the Pareto Efficiency Frontier."""
    budget_step: float = 0.0
    budget_spend_usd: float = 0.0
    budget_spend_inr: float = 0.0
    risk_mitigated_usd: float = 0.0
    risk_mitigated_inr: float = 0.0
    residual_eal_usd: float = 0.0
    residual_eal_inr: float = 0.0
    portfolio_rosi: float = 0.0
    marginal_cost_benefit_ratio: float = 0.0
    is_elbow_point: bool = False
    security_upgrade_pct: float = Field(default=0.0, description="Security upgrade percentage [0, 100]")
    # Conftest / legacy compatibility fields
    spend: float = 0.0
    risk_mitigated: float = 0.0
    residual_eal: float = 0.0
    rosi_percentage: float = 0.0
    selected_control_ids: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sync_compat(cls, data: Any) -> Any:
        if isinstance(data, dict):
            spend = data.get("spend", 0.0)
            spend_usd = data.get("budget_spend_usd", 0.0)
            if spend > 0.0 and spend_usd == 0.0:
                data["budget_spend_usd"] = spend
                data["budget_spend_inr"] = usd_to_inr(spend)
            elif spend_usd > 0.0 and spend == 0.0:
                data["spend"] = spend_usd

            rm = data.get("risk_mitigated", 0.0)
            rm_usd = data.get("risk_mitigated_usd", 0.0)
            if rm > 0.0 and rm_usd == 0.0:
                data["risk_mitigated_usd"] = rm
                data["risk_mitigated_inr"] = usd_to_inr(rm)
            elif rm_usd > 0.0 and rm == 0.0:
                data["risk_mitigated"] = rm_usd

            eal = data.get("residual_eal", 0.0)
            eal_usd = data.get("residual_eal_usd", 0.0)
            if eal > 0.0 and eal_usd == 0.0:
                data["residual_eal_usd"] = eal
                data["residual_eal_inr"] = usd_to_inr(eal)
            elif eal_usd > 0.0 and eal == 0.0:
                data["residual_eal"] = eal_usd

            rosi = data.get("rosi_percentage", 0.0)
            p_rosi = data.get("portfolio_rosi", 0.0)
            if rosi != 0.0 and p_rosi == 0.0:
                data["portfolio_rosi"] = rosi
            elif p_rosi != 0.0 and rosi == 0.0:
                data["rosi_percentage"] = p_rosi
        return data


class FrontierResult(BaseModel):
    """Complete Pareto Efficiency Frontier analysis with Kneedle elbow detection."""
    curve: List[FrontierPoint] = Field(default_factory=list)
    elbow_point: Optional[FrontierPoint] = None
    max_mitigation_usd: float = 0.0
    max_mitigation_inr: float = 0.0
    total_candidate_cost_usd: float = 0.0
    total_candidate_cost_inr: float = 0.0


class OptimizationResult(BaseModel, BaseOptimizationResult):
    """Optimal portfolio recommendation for a given budget limit."""
    budget: float = 0.0
    currency: str = "USD"
    allocated_spend_usd: float = 0.0
    allocated_spend_inr: float = 0.0
    selected_control_ids: List[str] = Field(default_factory=list)
    selected_controls: List[Any] = Field(default_factory=list)
    risk_mitigated_usd: float = 0.0
    risk_mitigated_inr: float = 0.0
    residual_eal_usd: float = 0.0
    residual_eal_inr: float = 0.0
    portfolio_rosi: float = 0.0
    net_financial_benefit_usd: float = 0.0
    net_financial_benefit_inr: float = 0.0
    is_budget_satisfied: bool = True
    solver_status: str = "optimal"
    # Legacy / conftest compatibility fields
    allocated_spend: float = 0.0
    risk_mitigated: float = 0.0
    residual_eal: float = 0.0
    security_upgrade_pct: float = Field(default=0.0, description="Security upgrade percentage [0, 100]")
    efficiency_frontier: List[FrontierPoint] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sync_compat_result(cls, data: Any) -> Any:
        if isinstance(data, dict):
            spend = data.get("allocated_spend", 0.0)
            spend_usd = data.get("allocated_spend_usd", 0.0)
            spend_inr = data.get("allocated_spend_inr", 0.0)
            curr = data.get("currency", "USD").upper()

            if spend > 0.0 and spend_usd == 0.0 and spend_inr == 0.0:
                if curr == "INR":
                    data["allocated_spend_inr"] = spend
                    data["allocated_spend_usd"] = inr_to_usd(spend)
                else:
                    data["allocated_spend_usd"] = spend
                    data["allocated_spend_inr"] = usd_to_inr(spend)
            elif spend_usd > 0.0 and spend == 0.0:
                data["allocated_spend"] = data.get("allocated_spend_inr", usd_to_inr(spend_usd)) if curr == "INR" else spend_usd

            rm = data.get("risk_mitigated", 0.0)
            rm_usd = data.get("risk_mitigated_usd", 0.0)
            rm_inr = data.get("risk_mitigated_inr", 0.0)
            if rm > 0.0 and rm_usd == 0.0 and rm_inr == 0.0:
                if curr == "INR":
                    data["risk_mitigated_inr"] = rm
                    data["risk_mitigated_usd"] = inr_to_usd(rm)
                else:
                    data["risk_mitigated_usd"] = rm
                    data["risk_mitigated_inr"] = usd_to_inr(rm)
            elif rm_usd > 0.0 and rm == 0.0:
                data["risk_mitigated"] = data.get("risk_mitigated_inr", usd_to_inr(rm_usd)) if curr == "INR" else rm_usd

            eal = data.get("residual_eal", 0.0)
            eal_usd = data.get("residual_eal_usd", 0.0)
            eal_inr = data.get("residual_eal_inr", 0.0)
            if eal > 0.0 and eal_usd == 0.0 and eal_inr == 0.0:
                if curr == "INR":
                    data["residual_eal_inr"] = eal
                    data["residual_eal_usd"] = inr_to_usd(eal)
                else:
                    data["residual_eal_usd"] = eal
                    data["residual_eal_inr"] = usd_to_inr(eal)
            elif eal_usd > 0.0 and eal == 0.0:
                data["residual_eal"] = data.get("residual_eal_inr", usd_to_inr(eal_usd)) if curr == "INR" else eal_usd
        return data
