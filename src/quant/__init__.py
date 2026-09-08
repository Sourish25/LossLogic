"""
src/quant - FAIR Continuous Financial Risk Quantification Engine.

Provides:
- FAIR standard parameter translation from multi-domain telemetry and asset graphs
- Vectorized Compound Poisson - LogNormal / Beta-PERT Monte Carlo loss simulation
- Value-at-Risk percentiles (VaR 90th, 95th, 99th), CVaR 95th, and Loss Exceedance Curves
- Multi-level portfolio aggregation across Asset -> Business Unit -> Enterprise
- Subadditive risk diversification benefit quantification
- Bit-exact deterministic seed reproducibility
"""

from src.quant.fair_mapper import (
    FairMapper,
    FairParameters,
    calculate_contact_frequency,
    calculate_primary_loss,
    calculate_probability_of_action,
    calculate_resistance_strength,
    calculate_secondary_loss,
    calculate_threat_capability,
    calculate_vulnerability,
    get_acs,
    get_data_sensitivity_multiplier,
    get_downtime_hourly_cost,
    get_tier_multiplier,
    pert_to_lognormal,
)
from src.quant.monte_carlo import (
    MonteCarloEngine,
    SimulationResult,
    simulate_asset_loss,
)
from src.quant.portfolio import (
    AssetRiskDetail,
    BusinessUnitRiskResult,
    PortfolioEngine,
    PortfolioRiskResult,
)

__all__ = [
    # FAIR parameter mapping
    "FairParameters",
    "FairMapper",
    "calculate_contact_frequency",
    "calculate_probability_of_action",
    "calculate_threat_capability",
    "calculate_resistance_strength",
    "calculate_vulnerability",
    "calculate_primary_loss",
    "calculate_secondary_loss",
    "get_tier_multiplier",
    "get_data_sensitivity_multiplier",
    "get_acs",
    "get_downtime_hourly_cost",
    "pert_to_lognormal",
    # Monte Carlo simulation
    "SimulationResult",
    "simulate_asset_loss",
    "MonteCarloEngine",
    # Portfolio aggregation
    "AssetRiskDetail",
    "BusinessUnitRiskResult",
    "PortfolioRiskResult",
    "PortfolioEngine",
]
