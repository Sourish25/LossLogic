"""
src/decision_support/narrative.py - Plain-Language Executive Narrative Generator.

Synthesizes complex Monte Carlo loss distributions, threat trajectories, What-If simulation deltas,
and optimization returns into executive board-level summaries:
- Formats currency in Indian (₹ Crores, Lakhs) and Western ($ Millions, Thousands) notations.
- Highlights top loss drivers (vulnerabilities and assets).
- Explains 30/60/90-day trajectory forecasts and dynamic threat velocity.
- Synthesizes actionable mitigation recommendations with spend, risk reduction, and ROSI %.
- References compliance frameworks (RBI CSF, SEBI, ISO 27001, NIST CSF).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from src.config import USD_TO_INR_RATE


def format_currency(amount: float, currency: str = "INR") -> str:
    """
    Formats a numeric amount into readable Indian or Western executive notation.
    Examples:
      - INR: ₹1.50 Crore, ₹45.00 Lakhs, ₹50,000
      - USD: $1.50M, $450.0k, $500
    """
    val = float(amount)
    curr = currency.upper().strip()

    if curr == "INR":
        if abs(val) >= 10_000_000.0:
            return f"₹{val / 10_000_000.0:.2f} Crore"
        elif abs(val) >= 100_000.0:
            return f"₹{val / 100_000.0:.2f} Lakhs"
        else:
            return f"₹{val:,.0f}"
    else:
        if abs(val) >= 1_000_000_000.0:
            return f"${val / 1_000_000_000.0:.2f}B"
        elif abs(val) >= 1_000_000.0:
            return f"${val / 1_000_000.0:.2f}M"
        elif abs(val) >= 1_000.0:
            return f"${val / 1_000.0:.1f}k"
        else:
            return f"${val:,.0f}"


class NarrativeReport(BaseModel):
    """Board-ready executive narrative report."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    headline: str = Field(..., description="Single-sentence bottom-line executive conclusion")
    board_ready_narrative: str = Field(..., description="Comprehensive multi-sentence executive briefing")
    key_metrics: Dict[str, Any] = Field(default_factory=dict, description="Key financial figures formatted")
    bulleted_recommendations: List[str] = Field(default_factory=list, description="Prioritized mitigation actions")
    trajectory_summary: str = Field(default="", description="Summary of 30/60/90-day trajectory trend")
    compliance_note: str = Field(default="", description="Regulatory compliance mapping context")
    currency: str = Field(default="INR", description="Reporting currency")


class ExecutiveNarrativeGenerator:
    """
    Translates quantitative technical and financial risk quantification outputs
    into clear, concise board-level briefings.
    """

    def __init__(self, default_currency: str = "INR") -> None:
        self.default_currency = default_currency

    def generate(
        self,
        eal: float,
        var_95: float,
        top_asset_name: str = "Core Assets",
        top_cve_id: Optional[str] = None,
        recommended_spend: float = 0.0,
        risk_reduction: float = 0.0,
        rosi_percent: Optional[float] = None,
        trajectory_growth_pct: float = 0.0,
        compliance_frameworks: Optional[List[str]] = None,
        currency: Optional[str] = None,
    ) -> NarrativeReport:
        """
        Generates an end-to-end executive risk narrative.
        """
        curr = (currency or self.default_currency).upper()
        formatted_eal = format_currency(eal, curr)
        formatted_var95 = format_currency(var_95, curr)
        formatted_spend = format_currency(recommended_spend, curr)
        formatted_reduction = format_currency(risk_reduction, curr)

        # Headline
        headline = (
            f"Enterprise annualized financial cyber exposure stands at {formatted_eal}, "
            f"with a 95th percentile Value-at-Risk of {formatted_var95}."
        )

        # Narrative body
        cve_clause = f" ({top_cve_id})" if top_cve_id else ""
        narrative_parts = [
            f"Enterprise annualized financial cyber exposure stands at {formatted_eal}.",
            f"The primary vulnerability{cve_clause} contributing to exposure resides in {top_asset_name}.",
        ]

        if recommended_spend > 0.0:
            rosi_str = f" a {rosi_percent:.0f}% Return on Security Investment." if rosi_percent else " positive net risk reduction."
            narrative_parts.append(
                f"By funding the recommended mitigation portfolio at a cost of {formatted_spend}, "
                f"tail risk is reduced with{rosi_str}"
            )
        else:
            narrative_parts.append(
                f"Immediate remediation of active vulnerabilities on {top_asset_name} is recommended to preserve resilience."
            )

        board_ready_narrative = " ".join(narrative_parts)

        # Recommendations
        recommendations = [
            f"Prioritize remediation on {top_asset_name} to mitigate primary loss driver.",
            f"Deploy controls with positive marginal benefit to reduce {formatted_eal} annual loss.",
        ]
        if recommended_spend > 0.0:
            recommendations.append(f"Allocate {formatted_spend} budget toward high-ROSI security mitigations.")

        # Trajectory summary
        if trajectory_growth_pct != 0.0:
            trend_word = "surge" if trajectory_growth_pct > 0 else "decline"
            traj_text = (
                f"Threat velocity and exploit weaponization are projected to drive a {abs(trajectory_growth_pct):.1f}% "
                f"{trend_word} in exposure over the next 90 days if left unmitigated."
            )
        else:
            traj_text = "Risk trajectory remains stable under current threat contact velocity."

        # Compliance note
        fw_list = compliance_frameworks or ["RBI CSF", "SEBI CSCRF", "ISO 27001"]
        comp_note = (
            f"Mitigations align with mandatory control safeguards specified by {', '.join(fw_list)}."
        )

        key_metrics = {
            "expected_annual_loss": eal,
            "formatted_eal": formatted_eal,
            "var_95": var_95,
            "formatted_var_95": formatted_var95,
            "recommended_spend": recommended_spend,
            "formatted_spend": formatted_spend,
            "risk_reduction": risk_reduction,
            "formatted_reduction": formatted_reduction,
            "rosi_percent": rosi_percent,
            "top_asset": top_asset_name,
            "top_cve": top_cve_id,
            "currency": curr,
        }

        return NarrativeReport(
            headline=headline,
            board_ready_narrative=board_ready_narrative,
            key_metrics=key_metrics,
            bulleted_recommendations=recommendations,
            trajectory_summary=traj_text,
            compliance_note=comp_note,
            currency=curr,
        )


def generate_executive_narrative(
    eal: float,
    var_95: float,
    top_asset: str = "Core Payment Gateway",
    spend: float = 0.0,
    rosi: Optional[float] = None,
    currency: str = "INR",
    top_cve: Optional[str] = None,
    trajectory_growth: float = 0.0,
) -> NarrativeReport:
    """
    Authoritative reference function for executive narrative generation.
    """
    generator = ExecutiveNarrativeGenerator(default_currency=currency)
    return generator.generate(
        eal=eal,
        var_95=var_95,
        top_asset_name=top_asset,
        top_cve_id=top_cve,
        recommended_spend=spend,
        risk_reduction=spend * ((rosi or 100.0) / 100.0 + 1.0) if spend > 0 else 0.0,
        rosi_percent=rosi,
        trajectory_growth_pct=trajectory_growth,
        currency=currency,
    )
