"""
src/decision_support/ - AI Decision Support, Natural Language Query & Scenario Simulation.

Exports:
- ThreatTrajectoryForecaster, TrajectoryPoint, TrajectoryForecast, TrajectoryScenario
- WhatIfEngine, WhatIfRequest, WhatIfResult, run_counterfactual_simulation
- DelayedRemediationModel, DelayPoint, DelayCostResult, calculate_delay_cost
- NLQParser, QueryIntent, ExtractedEntities, StructuredRiskQuery, parse_nlq_query, NLQRouter
- ExecutiveNarrativeGenerator, NarrativeReport, generate_executive_narrative, format_currency
"""

from src.decision_support.delay_cost import (
    DelayCostResult,
    DelayedRemediationModel,
    DelayPoint,
    calculate_delay_cost,
)
from src.decision_support.narrative import (
    ExecutiveNarrativeGenerator,
    NarrativeReport,
    format_currency,
    generate_executive_narrative,
)
from src.decision_support.nlq_parser import (
    ExtractedEntities,
    NLQParser,
    NLQRouter,
    QueryIntent,
    StructuredRiskQuery,
    parse_nlq_query,
)
from src.decision_support.trajectory import (
    ThreatTrajectoryForecaster,
    TrajectoryForecast,
    TrajectoryPoint,
    TrajectoryScenario,
)
from src.decision_support.what_if import (
    WhatIfEngine,
    WhatIfRequest,
    WhatIfResult,
    run_counterfactual_simulation,
)

__all__ = [
    # Trajectory
    "ThreatTrajectoryForecaster",
    "TrajectoryPoint",
    "TrajectoryForecast",
    "TrajectoryScenario",
    # What-If
    "WhatIfEngine",
    "WhatIfRequest",
    "WhatIfResult",
    "run_counterfactual_simulation",
    # Delay Cost
    "DelayedRemediationModel",
    "DelayPoint",
    "DelayCostResult",
    "calculate_delay_cost",
    # NLQ
    "NLQParser",
    "NLQRouter",
    "QueryIntent",
    "ExtractedEntities",
    "StructuredRiskQuery",
    "parse_nlq_query",
    # Narrative
    "ExecutiveNarrativeGenerator",
    "NarrativeReport",
    "generate_executive_narrative",
    "format_currency",
]
