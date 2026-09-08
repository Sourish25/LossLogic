"""
src/api/schemas.py - Pydantic Request and Response DTOs for the CyberRiskQuant API.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


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
