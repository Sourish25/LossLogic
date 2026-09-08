"""
CyberRiskQuant Optimization Package (Milestone 4 - Budget-Constrained Investment Optimization).
"""

from src.optimization.models import (
    FrontierPoint,
    FrontierResult,
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
)
from src.optimization.rosi import (
    calculate_marginal_cbr,
    calculate_net_financial_benefit,
    calculate_rosi,
    convert_currency,
    format_currency,
    format_inr,
    format_usd,
)
from src.optimization.frontier import (
    detect_elbow_point,
    generate_pareto_frontier,
)
from src.optimization.solver import OptimizationSolver

__all__ = [
    "OptimizationSolver",
    "SecurityControl",
    "OptimizationRequest",
    "OptimizationResult",
    "FrontierPoint",
    "FrontierResult",
    "calculate_rosi",
    "calculate_net_financial_benefit",
    "calculate_marginal_cbr",
    "format_currency",
    "format_inr",
    "format_usd",
    "convert_currency",
    "generate_pareto_frontier",
    "detect_elbow_point",
]
