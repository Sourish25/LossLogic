"""
src/optimization/__init__.py - Optimization, ROSI, and Vendor Benchmarking Module.
"""

from src.optimization.models import (
    FrontierPoint,
    FrontierResult,
    OptimizationRequest,
    OptimizationResult,
    SecurityControl,
    ThreatShield,
    ThreatVectorEnum,
)
from src.optimization.rosi import (
    calculate_marginal_cbr,
    calculate_net_capital_saved,
    calculate_net_financial_benefit,
    calculate_rosi,
    calculate_security_posture_score,
    calculate_security_upgrade_pct,
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
from src.optimization.vendor_benchmarking import (
    VENDOR_CATALOG,
    VendorCategoryEnum,
    VendorProductProfile,
    apply_virtual_vendor_purchase,
    get_ceo_vendor_catalog,
    get_vendor_by_id,
)

__all__ = [
    # Solvers & Core Models
    "OptimizationSolver",
    "SecurityControl",
    "OptimizationRequest",
    "OptimizationResult",
    "FrontierPoint",
    "FrontierResult",
    "ThreatVectorEnum",
    "ThreatShield",
    # ROSI & Posture Metrics
    "calculate_rosi",
    "calculate_net_financial_benefit",
    "calculate_marginal_cbr",
    "calculate_security_upgrade_pct",
    "calculate_net_capital_saved",
    "calculate_security_posture_score",
    "format_currency",
    "format_inr",
    "format_usd",
    "convert_currency",
    # Frontier Curves
    "generate_pareto_frontier",
    "detect_elbow_point",
    # Vendor Benchmarking
    "VendorCategoryEnum",
    "VendorProductProfile",
    "VENDOR_CATALOG",
    "get_ceo_vendor_catalog",
    "get_vendor_by_id",
    "apply_virtual_vendor_purchase",
]
