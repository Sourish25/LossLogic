"""
src/optimization/rosi.py - Financial Return on Security Investment (ROSI) Calculator.
"""

import math
from src.config import USD_TO_INR_RATE, INR_TO_USD_RATE, usd_to_inr, inr_to_usd


def calculate_rosi(risk_mitigated: float, cost: float) -> float:
    """
    Calculate Return on Security Investment (ROSI) percentage.

    ROSI % = ((Risk Mitigated - Cost) / Cost) * 100.0 (when Cost > 0, else 0.0).
    A positive percentage indicates net financial risk reduction beyond implementation cost.
    """
    if cost <= 0.0:
        return 0.0
    return ((risk_mitigated - cost) / cost) * 100.0


def calculate_net_financial_benefit(risk_mitigated: float, cost: float) -> float:
    """
    Calculate Net Financial Benefit (NFB).

    NFB = Risk Mitigated - Cost (in base currency).
    """
    return risk_mitigated - cost


def calculate_marginal_cbr(risk_mitigated: float, cost: float) -> float:
    """
    Calculate Marginal Cost-Benefit Ratio (CBR).

    CBR = Risk Mitigated / Cost.
    Measures monetary risk reduction achieved per unit of currency spent.
    """
    if cost <= 0.0:
        return 0.0
    return risk_mitigated / cost


def calculate_security_upgrade_pct(risk_mitigated: float, baseline_exposure: float) -> float:
    """
    Calculate explicit Security Upgrade Percentage (SUP %):
    The exact resilience boost achieved for a given financial investment:

        SUP % = (Risk Mitigated / Baseline Enterprise Exposure) * 100.0%

    Mathematical Invariants:
    - Bounded strictly within [0.0, 100.0].
    - Zero-division safe: returns 0.0 if baseline_exposure <= 0.0.
    - Non-negative: returns 0.0 if risk_mitigated <= 0.0.
    - Capped at 100.0 when risk_mitigated >= baseline_exposure.
    - Handles NaN and infinite inputs safely.
    """
    if math.isnan(risk_mitigated) or math.isnan(baseline_exposure):
        return 0.0
    if math.isinf(risk_mitigated) or math.isinf(baseline_exposure):
        return 0.0
    if baseline_exposure <= 0.0 or risk_mitigated <= 0.0:
        return 0.0

    raw_pct = (risk_mitigated / baseline_exposure) * 100.0
    return round(min(100.0, max(0.0, raw_pct)), 2)


def calculate_net_capital_saved(baseline_eal: float, residual_eal: float) -> float:
    """
    Calculate Net Capital Saved (annualized financial loss prevented in real currency):

        Net Capital Saved = max(0.0, baseline_eal - residual_eal)

    Mathematical Invariants:
    - Guaranteed non-negative (>= 0.0).
    - If residual_eal >= baseline_eal (e.g. during an unmitigated attack spike), returns 0.0.
    - Handles NaN and infinite inputs safely.
    - Post-subtraction overflow guard ensures result is always a finite float.
    """
    if math.isnan(baseline_eal) or math.isnan(residual_eal):
        return 0.0
    if math.isinf(baseline_eal) or math.isinf(residual_eal):
        return 0.0

    saved = baseline_eal - residual_eal
    if math.isinf(saved) or math.isnan(saved):
        return 0.0
    return round(max(0.0, float(saved)), 2)


def calculate_security_posture_score(
    baseline_eal: float,
    current_eal: float,
    control_count: int = 0
) -> float:
    """
    Calculate unified Cyber Security Posture Score on a [0.0, 100.0] scale.

    Combines:
    1. Financial risk mitigation ratio: (baseline_eal - current_eal) / baseline_eal
    2. Defense-in-depth control breadth: based on active/funded control count

    Calibrated Score Profiles:
    - Baseline Unmitigated (current_eal == baseline_eal, control_count == 1): ~42.5 (Elevated Exposure)
    - Fully Unmitigated with 0 controls: 40.0
    - Typical Funded Portfolio (80% mitigation, 6 controls): 91.0 (Resilient / Hardened)
    - Full Catalog Hardened (100% mitigation, 6+ controls): 100.0 (Optimal Immunity)
    - Active Attack Surge (current_eal = 1.5 * baseline_eal, 1 control): 20.0 (High Risk / Critical)
    - Catastrophic Attack Surge (current_eal >= 2.0 * baseline_eal): clamped to 0.0

    Mathematical Invariants:
    - Strictly bounded in [0.0, 100.0].
    - Zero-division guarded: if baseline_eal <= 0.0, returns 100.0 if current_eal <= 0.0 else 0.0.
    - Handles NaN and infinite inputs safely.
    """
    if math.isnan(baseline_eal) or math.isnan(current_eal):
        return 0.0
    if math.isinf(baseline_eal) or math.isinf(current_eal):
        return 0.0
    if baseline_eal <= 0.0:
        return 100.0 if current_eal <= 0.0 else 0.0

    # Risk mitigation fraction: positive when mitigated, negative when under attack
    risk_mitigation_ratio = (baseline_eal - current_eal) / baseline_eal

    # Baseline score of unmitigated enterprise
    base_score = 40.0

    # Financial mitigation component: maps ratio into [-45.0, +45.0]
    mitigation_component = risk_mitigation_ratio * 45.0

    # Defense-in-depth control breadth bonus: up to 15.0 points (2.5 per control, max 6 controls)
    ctrl_c = max(0, int(control_count))
    control_bonus = min(15.0, ctrl_c * 2.5)

    raw_score = base_score + mitigation_component + control_bonus
    return round(min(100.0, max(0.0, raw_score)), 1)



def format_inr(amount: float) -> str:
    """
    Format amount in Indian numbering system (Lakhs, Crores).
    """
    abs_amt = abs(amount)
    sign = "-" if amount < 0 else ""
    if abs_amt >= 10_000_000.0:  # 1 Crore = 10,000,000
        return f"{sign}₹{abs_amt / 10_000_000.0:.2f} Crore"
    elif abs_amt >= 100_000.0:   # 1 Lakh = 100,000
        return f"{sign}₹{abs_amt / 100_000.0:.2f} Lakhs"
    else:
        return f"{sign}₹{abs_amt:,.2f}"


def format_usd(amount: float) -> str:
    """
    Format amount in US Dollar conventions ($ Billions, Millions, Thousands).
    """
    abs_amt = abs(amount)
    sign = "-" if amount < 0 else ""
    if abs_amt >= 1_000_000_000.0:
        return f"{sign}${abs_amt / 1_000_000_000.0:.2f}B"
    elif abs_amt >= 1_000_000.0:
        return f"{sign}${abs_amt / 1_000_000.0:.2f}M"
    elif abs_amt >= 1_000.0:
        return f"{sign}${abs_amt / 1_000.0:.2f}K"
    else:
        return f"{sign}${abs_amt:,.2f}"


def format_currency(amount: float, currency: str = "USD") -> str:
    """
    Format monetary amounts using appropriate regional convention.
    """
    if currency.upper() == "INR":
        return format_inr(amount)
    return format_usd(amount)


def convert_currency(amount: float, from_currency: str, to_currency: str) -> float:
    """
    Convert amount between USD and INR using global enterprise exchange rates.
    """
    from_c = from_currency.upper()
    to_c = to_currency.upper()
    if from_c == to_c:
        return float(amount)
    if from_c == "USD" and to_c == "INR":
        return usd_to_inr(amount)
    if from_c == "INR" and to_c == "USD":
        return inr_to_usd(amount)
    raise ValueError(f"Unsupported currency conversion: {from_currency} -> {to_currency}")
