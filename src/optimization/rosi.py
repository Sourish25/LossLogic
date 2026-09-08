"""
src/optimization/rosi.py - Financial Return on Security Investment (ROSI) Calculator.
"""

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
