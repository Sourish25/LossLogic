"""
src/api/schemas.py - Pydantic Request and Response DTOs for the CyberRiskQuant API.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class HealthResponse(BaseModel):
    """System health and readiness status."""
    status: str = "healthy"
    version: str = "1.0.0"
    engine: str = "FAIR Monte Carlo + SciPy HiGHS MILP"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TopLossDriver(BaseModel):
    """Summary of asset-level risk contribution."""
    asset: str
    loss: float
    domain: Optional[str] = None
    severity: Optional[str] = None


class ExecutiveDashboardResponse(BaseModel):
    """Executive Board & CISO high-level quantitative cyber risk summary."""
    model_config = ConfigDict(populate_by_name=True)

    currency: str = "INR"
    total_eal: float = Field(..., description="Expected Annual Loss in selected currency")
    eal_trend_pct: float = Field(default=0.0, description="Quarter-over-quarter EAL trajectory percentage")
    var_90: float = Field(..., description="90th percentile Value-at-Risk")
    var_95: float = Field(..., description="95th percentile Value-at-Risk")
    var_99: float = Field(..., description="99th percentile Value-at-Risk (tail catastrophe)")
    compliance_pct: float = Field(..., ge=0.0, le=100.0, description="Composite regulatory compliance score")
    top_loss_drivers: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_budget: float = Field(default=0.0)
    recommended_risk_reduction: float = Field(default=0.0)
    recommended_rosi: float = Field(default=0.0, description="Return on Security Investment percentage")
    loss_exceedance_curve: List[Dict[str, float]] = Field(default_factory=list)
    trajectory: Dict[str, float] = Field(default_factory=dict)


class TechnicalDashboardResponse(BaseModel):
    """SecOps and technical findings drilldown summary."""
    model_config = ConfigDict(populate_by_name=True)

    currency: str = "INR"
    domain_counts: Dict[str, int] = Field(default_factory=dict)
    critical_findings_count: int = 0
    high_findings_count: int = 0
    total_findings: int = 0
    assets_at_risk: int = 0
    backlog: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: Dict[str, Any] = Field(default_factory=dict)


class SimulationRequest(BaseModel):
    """Risk simulation parameters."""
    iterations: int = Field(default=5000, ge=100, le=50000)
    seed: Optional[int] = Field(default=42)
    currency: str = Field(default="INR")


class SimulationResponse(BaseModel):
    """Monte Carlo risk simulation results."""
    eal: float
    var_90: float
    var_95: float
    var_99: float
    currency: str = "INR"
    execution_time_ms: float
    asset_risks: Dict[str, float] = Field(default_factory=dict)
    loss_exceedance_curve: List[Dict[str, float]] = Field(default_factory=list)


class WhatIfRequest(BaseModel):
    """Counterfactual scenario simulation request."""
    implemented_control_ids: List[str] = Field(default_factory=list)
    delay_days: int = Field(default=0, ge=0)
    currency: str = Field(default="INR")


class WhatIfResponse(BaseModel):
    """What-if scenario comparison results."""
    baseline_eal: float
    simulated_eal: float
    risk_delta: float
    risk_reduction_pct: float
    delay_penalty_cost: float
    currency: str = "INR"
    narrative: str = ""


class NLQRequest(BaseModel):
    """Plain-language natural language query."""
    query: str = Field(..., min_length=2)
    currency: str = Field(default="INR")


class NLQResponse(BaseModel):
    """Parsed query and generated executive narrative answer."""
    query: str
    intent: str
    confidence: float
    entities: Dict[str, Any] = Field(default_factory=dict)
    narrative_answer: str
    currency: str = "INR"


class OptimizeRequest(BaseModel):
    """Budget-constrained investment portfolio optimization request."""
    budget: float = Field(..., ge=0.0)
    currency: str = Field(default="INR")
    include_frontier: bool = Field(default=False)


class OptimizeResponse(BaseModel):
    """Optimal mitigation portfolio and financial return metrics."""
    budget: float
    allocated_spend: float
    risk_mitigated: float
    residual_eal: float
    portfolio_rosi: float
    selected_controls: List[Dict[str, Any]] = Field(default_factory=list)
    efficiency_frontier: Optional[List[Dict[str, Any]]] = None
    currency: str = "INR"


class ComplianceMatrixResponse(BaseModel):
    """Regulatory framework compliance scores and financial risk exposures."""
    composite_compliance_pct: float
    total_attributed_exposure: float
    currency: str = "INR"
    frameworks: Dict[str, Any] = Field(default_factory=dict)


class TelemetryDrilldownResponse(BaseModel):
    """Granular findings for a specific telemetry domain."""
    domain: str
    count: int
    findings: List[Dict[str, Any]] = Field(default_factory=list)


# =========================================================================
# Live Hackathon Demonstration Contracts (R1 - R5)
# =========================================================================

class DemoAttackType(str, Enum):
    """Supported attack scenarios for live BharatCart demonstration."""
    DDOS_SURGE = "ddos_surge"
    RANSOMWARE_OUTAGE = "ransomware_outage"
    SQL_DATA_LEAK = "sql_data_leak"
    CREDENTIAL_STUFFING = "credential_stuffing"


class BharatCartNode(str, Enum):
    """Critical service nodes comprising the BharatCart e-commerce topology."""
    API_GATEWAY = "BC-API-GW-01"
    FLASH_SALE = "BC-FLASH-SALE-01"
    PAYMENT_GATEWAY = "BC-PAY-GW-01"
    PII_VAULT = "BC-PII-VAULT-01"


class AttackInjectionRequest(BaseModel):
    """
    Payload for POST /api/v1/demo/inject-attack.
    Permits multi-device, unauthenticated injection from smartphones and external laptops.
    """
    attack_type: str = Field(
        ...,
        description="Attack scenario: 'ddos_surge', 'ransomware_outage', 'sql_data_leak', or 'credential_stuffing'"
    )
    target_node: Optional[str] = Field(
        default=None,
        description="Target node ID (e.g. 'BC-API-GW-01', 'BC-FLASH-SALE-01', 'BC-PAY-GW-01', 'BC-PII-VAULT-01') or friendly name"
    )
    intensity: float = Field(
        default=5.0,
        ge=1.0,
        le=10.0,
        description="Attack intensity multiplier (1.0 to 10.0, default 5.0)"
    )
    source_device: Optional[str] = Field(
        default="Remote Network Device",
        description="Identifying label for the injecting client (e.g. 'Jury iPhone 15 Pro', 'External SecOps Laptop')"
    )

    @field_validator("attack_type")
    @classmethod
    def normalize_attack_type(cls, v: str) -> str:
        clean = v.lower().strip().replace(" ", "_").replace("-", "_")
        if "ddos" in clean:
            return "ddos_surge"
        if "ransomware" in clean:
            return "ransomware_outage"
        if "sql" in clean or "leak" in clean or "exfil" in clean:
            return "sql_data_leak"
        if "credential" in clean or "stuffing" in clean or "login" in clean:
            return "credential_stuffing"
        if "zero_day" in clean or "cve" in clean:
            return "zero_day_cve"
        if "cloud_iam" in clean or "iam_compromise" in clean or "privilege_escalation" in clean:
            return "cloud_iam_compromise"
        valid = {
            "ddos_surge",
            "ransomware_outage",
            "sql_data_leak",
            "credential_stuffing",
            "zero_day_cve",
            "cloud_iam_compromise",
        }
        if clean not in valid:
            raise ValueError(f"Invalid attack_type '{v}'. Must be one of {valid}")
        return clean

    @field_validator("target_node")
    @classmethod
    def normalize_target_node(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        clean = v.strip()
        if not clean:
            return None

        valid_nodes = {
            "BC-API-GW-01",
            "BC-FLASH-SALE-01",
            "BC-PAY-GW-01",
            "BC-PII-VAULT-01",
        }
        if clean.upper() in valid_nodes:
            return clean.upper()

        clean_lower = clean.lower()
        if "gateway" in clean_lower or "gw" in clean_lower or "kong" in clean_lower:
            return "BC-API-GW-01"
        if "sale" in clean_lower or "k8s" in clean_lower or "order" in clean_lower:
            return "BC-FLASH-SALE-01"
        if "pay" in clean_lower or "stripe" in clean_lower or "auth" in clean_lower:
            return "BC-PAY-GW-01"
        if "vault" in clean_lower or "pii" in clean_lower or "db" in clean_lower or "sql" in clean_lower:
            return "BC-PII-VAULT-01"

        raise ValueError(
            f"Invalid target_node '{v}'. Must be one of {sorted(valid_nodes)} or recognized service alias."
        )


class AttackInjectionResponse(BaseModel):
    """
    Response returned upon successful attack injection.
    Supports both UI contracts and analytics models seamlessly.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    success: bool = True
    attack_id: str = Field(..., description="Unique UUID identifying attack instance")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attack_type: str
    target_node: str
    intensity: float = 5.0
    status: str = "INJECTED"
    tef_spike_multiplier: float = Field(default=1.0, description="Multiplier applied to Threat Event Frequency")
    tef_spike_factor: float = Field(default=1.0, description="Alias for tef_spike_multiplier")
    nominal_tef: float = 12.0
    spiked_tef: float = 12.0
    baseline_eal_inr: float = Field(default=48_200_000.0, description="Baseline EAL in INR")
    baseline_eal: float = Field(default=48_200_000.0, description="Baseline EAL prior to attack")
    direct_loss_inr: float = 0.0
    cascading_loss_inr: float = 0.0
    total_surge_inr: float = 0.0
    eal_surge_inr: float = Field(default=0.0, description="EAL surge delta in INR")
    eal_delta: float = Field(default=0.0, description="Alias for eal_surge_inr")
    spiked_eal_inr: float = Field(default=48_200_000.0, description="Spiked EAL in INR")
    new_eal_inr: float = Field(default=48_200_000.0, description="Alias for spiked_eal_inr")
    spiked_eal: float = Field(default=48_200_000.0, description="Explicit alias for spiked_eal_inr")
    spiked_eal_usd: float = 0.0
    new_eal_usd: float = 0.0
    posture_before: float = Field(default=84.6, ge=0.0, le=100.0, description="Posture score before attack")
    posture_after: float = Field(default=52.0, ge=0.0, le=100.0, description="Posture score after attack")
    posture_degradation_pts: float = Field(default=32.6, description="Drop in posture score points")
    posture_degradation_pct: float = Field(default=-32.6, description="Percentage/point drop in posture")
    posture_drift_pct: float = Field(default=-32.6, description="Percentage drift in posture relative to baseline")
    var_90_inr: float = Field(default=82_000_000.0, description="Spiked Value-at-Risk 90th percentile in INR")
    var_95_inr: float = Field(default=124_000_000.0, description="Spiked Value-at-Risk 95th percentile in INR")
    var_99_inr: float = Field(default=241_000_000.0, description="Spiked Value-at-Risk 99th percentile in INR")
    recommended_control_id: str = Field(default="", description="Control ID corresponding to countermeasure")
    recommended_product_id: str = Field(default="", description="Product ID corresponding to vendor countermeasure")
    recommended_countermeasure: str = Field(default="", description="Recommended mitigation message")
    neutralization_efficacy_pct: float = Field(default=99.0, description="Percentage efficacy of countermeasure")
    source_device: str = "Remote Network Device"
    currency: str = "INR"


class TelemetryTickerResponse(BaseModel):
    """
    Payload emitted by GET /api/v1/demo/telemetry-ticker every 2-3 seconds.
    Emulates dynamic, non-hardcoded stochastic background telemetry.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_threat_level: str = Field(default="NORMAL", description="'NORMAL', 'ELEVATED', or 'CRITICAL_ATTACK_ACTIVE'")
    threat_level: str = Field(default="NORMAL", description="Alias for overall_threat_level")
    tef_current: float = Field(default=12.4, ge=0.0, description="Current Threat Event Frequency jitter")
    threat_event_frequency: float = Field(default=12.4, ge=0.0, description="Alias for tef_current")
    eps_current: float = Field(default=14850.0, ge=0.0, description="Current Events Per Second jitter")
    events_per_second: float = Field(default=14850.0, ge=0.0, description="Alias for eps_current")
    active_alerts_count: int = Field(default=11, ge=0, description="Current active SOC alerts count")
    posture_score: float = Field(default=84.6, ge=0.0, le=100.0, description="Live enterprise posture score")
    current_posture_score: float = Field(default=84.6, ge=0.0, le=100.0, description="Alias for posture_score")
    security_posture_score: float = Field(default=84.6, ge=0.0, le=100.0, description="Alias for posture_score")
    posture_drift_pct: float = Field(default=0.0, description="Live percentage drift in posture relative to baseline")
    risk_factor_score: float = Field(default=4.8, ge=0.0, le=10.0, description="Real-time risk factor multiplier")
    current_eal_inr: float = Field(default=48_200_000.0, ge=0.0, description="Current enterprise EAL in INR")
    var_90_inr: float = Field(default=82_000_000.0, description="Live Value-at-Risk 90th percentile in INR")
    var_95_inr: float = Field(default=124_000_000.0, description="Live Value-at-Risk 95th percentile in INR")
    var_99_inr: float = Field(default=241_000_000.0, description="Live Value-at-Risk 99th percentile in INR")
    has_active_attack: bool = False
    active_attack: bool = False
    attack_type: Optional[str] = None
    target_node: Optional[str] = None
    total_threat_shields_active: int = 5
    purchased_vendors_count: int = 0
    active_attacks_count: int = Field(default=0, ge=0)
    active_attacks: List[Dict[str, Any]] = Field(default_factory=list)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    active_attack_details: Optional[Dict[str, Any]] = None


class ResetAttackResponse(BaseModel):
    """Response returned upon resetting demonstration state."""
    success: bool = True
    status: str = "RESET_COMPLETED"
    active_attack: bool = False
    message: str = "BharatCart demonstration environment successfully restored to nominal baseline."
    baseline_eal_inr: float = 48_200_000.0
    baseline_eal: float = 48_200_000.0
    current_eal: float = 48_200_000.0
    baseline_posture: float = 84.6
    posture_score: float = 84.6
    active_attacks_cleared: int = 0
    currency: str = "INR"


class VendorComparisonResponse(BaseModel):
    """Response payload for GET /api/v1/vendor-benchmark/matrix."""
    currency: str = "INR"
    categories: List[str] = ["EDR", "WAF", "IAM", "CSPM"]
    vendors: List[Dict[str, Any]] = Field(default_factory=list)
    active_purchases: List[str] = Field(default_factory=list)
    total_vendor_spend: float = 0.0


class VirtualPurchaseRequest(BaseModel):
    """Payload for POST /api/v1/vendor-benchmark/purchase (one-click virtual purchase)."""
    vendor_id: str = Field(..., description="ID of vendor product (e.g. 'VND-CRWD-EDR', 'VND-CLDF-WAF')")
    currency: str = Field(default="INR", description="'INR' or 'USD'")


class VirtualPurchaseResponse(BaseModel):
    """Response returned upon 1-click virtual vendor purchase."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    vendor_id: str
    canonical_vendor_id: Optional[str] = None
    product_name: str
    vendor_name: str
    category: str
    allocated_spend: float
    allocated_spend_inr: float
    allocated_spend_usd: float
    baseline_eal: float
    residual_eal: float
    risk_mitigated: float
    security_upgrade_pct: float
    security_factor_score: float
    net_capital_saved: Optional[float] = Field(default=0.0, description="Net capital saved in current currency")
    security_posture_score: Optional[float] = Field(default=0.0, description="Actuarial security posture score [0-100]")
    posture_score: Optional[float] = Field(default=84.6, description="Alias for security_posture_score")
    risk_factor: Optional[float] = Field(default=4.8, description="Real-time risk factor multiplier")
    future_shields_unlocked: int = Field(default=2, description="Number of future threat shields unlocked")
    portfolio_rosi: Optional[float] = Field(default=0.0, description="Return on Security Investment percentage")
    currency: str = "INR"
    status: str = "PURCHASED"
    purchased_vendor_ids: List[str] = Field(default_factory=list)


# --- Google Gemini 3.5 Flash Lite AI Copilot & Action Engine Schemas ---


class AIChatRequest(BaseModel):
    """Payload for POST /api/v1/ai/chat."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    message: str = Field(..., min_length=1, description="User question or cyber risk query")
    history: List[Dict[str, str]] = Field(default_factory=list, description="Previous conversation turn history")
    currency: str = Field(default="INR", description="'INR' or 'USD'")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional client-side telemetry or active view context")


class AIChatResponse(BaseModel):
    """Response payload for POST /api/v1/ai/chat."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    response: str = Field(..., description="Markdown-formatted conversational response grounded in live state")
    reply: Optional[str] = Field(default=None, description="Alias for response")
    model_used: str = Field(default="gemini-3.5-flash-lite", description="Model name or 'local-heuristic-fallback'")
    grounded_metrics: Dict[str, Any] = Field(default_factory=dict, description="Live platform metrics snapshot")
    suggested_actions: List[Dict[str, Any]] = Field(default_factory=list, description="Interactive action chips")
    suggested_followups: List[str] = Field(default_factory=list, description="Follow-up question suggestions")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    offline_fallback: bool = Field(default=False, description="True if served by offline heuristic engine")
    execution_time_ms: float = Field(default=0.0, description="Round-trip latency in milliseconds")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.reply is None:
            self.reply = self.response


from src.ai.actions import ActionPayload


class AINavigateRequest(BaseModel):
    """Payload for POST /api/v1/ai/navigate."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    command: str = Field(..., min_length=1, description="Natural language navigation or parameter adjustment instruction")
    currency: str = Field(default="INR", description="'INR' or 'USD'")


class AINavigateResponse(BaseModel):
    """Response payload for POST /api/v1/ai/navigate."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    interpreted_command: str = Field(..., description="Original user command")
    intent: str = Field(default="NAVIGATE_TAB", description="Classified intent")
    confidence: float = Field(default=0.95, description="Classifier confidence score")
    actions: List[ActionPayload] = Field(default_factory=list, description="Sequence of executable action payloads")
    action: Optional[ActionPayload] = Field(default=None, description="Primary action payload")
    action_type: Optional[str] = Field(default=None, description="Direct shortcut to primary action type")
    target_tab: Optional[str] = Field(default=None, description="Direct shortcut to target tab")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Direct shortcut to primary parameters")
    explanation: str = Field(default="", description="Explanation of interpreted action")
    message: str = Field(default="", description="Alias for explanation")
    model_used: str = Field(default="gemini-3.5-flash-lite")
    offline_fallback: bool = Field(default=False)
    execution_time_ms: float = Field(default=0.0)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if not self.message and self.explanation:
            self.message = self.explanation
        if not self.explanation and self.message:
            self.explanation = self.message
        if self.action is None and self.actions:
            self.action = self.actions[-1]
        if self.action_type is None and self.action:
            self.action_type = self.action.action_type
        if self.target_tab is None and self.action and self.action.target_tab:
            self.target_tab = self.action.target_tab
        if not self.parameters and self.action and self.action.parameters:
            self.parameters = self.action.parameters


class AIExecutiveSummaryRequest(BaseModel):
    """Payload for POST /api/v1/ai/executive-summary."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    target_audience: Optional[str] = Field(default="jury", description="'jury', 'board', 'ciso', or 'ceo'")
    audience: Optional[str] = Field(default=None, description="Alias for target_audience")
    currency: str = Field(default="INR", description="'INR' or 'USD'")
    focus_domain: Optional[str] = Field(default=None, description="Optional domain focus")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.target_audience is None and self.audience is not None:
            self.target_audience = self.audience
        elif self.target_audience is not None and self.audience is None:
            self.audience = self.target_audience


class AIExecutiveSummaryResponse(BaseModel):
    """Response payload for POST /api/v1/ai/executive-summary."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    headline: str = Field(..., description="Concise executive headline")
    board_headline: Optional[str] = Field(default=None, description="Alias for headline")
    elevator_pitch_30s: str = Field(..., description="30-second elevator pitch for presentation")
    elevator_pitch: Optional[str] = Field(default=None, description="Alias for elevator_pitch_30s")
    summary_30s: Optional[str] = Field(default=None, description="Alias for elevator_pitch_30s")
    summary: Optional[str] = Field(default=None, description="Alias for elevator_pitch_30s")
    bulleted_insights: List[str] = Field(default_factory=list, description="Key quantitative takeaway bullets")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended strategic mitigations")
    posture_assessment: str = Field(default="", description="Current security posture evaluation")
    top_exposure: Dict[str, Any] = Field(default_factory=dict, description="Highest contributor to risk")
    recommended_capital_allocation: Dict[str, Any] = Field(default_factory=dict, description="HiGHS MILP spend & ROSI")
    key_metrics: Dict[str, Any] = Field(default_factory=dict, description="Live platform metrics snapshot")
    model_used: str = Field(default="gemini-3.5-flash-lite")
    offline_fallback: bool = Field(default=False)
    execution_time_ms: float = Field(default=0.0)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.board_headline is None:
            self.board_headline = self.headline
        if self.elevator_pitch is None:
            self.elevator_pitch = self.elevator_pitch_30s
        if self.summary_30s is None:
            self.summary_30s = self.elevator_pitch_30s
        if self.summary is None:
            self.summary = self.elevator_pitch_30s

