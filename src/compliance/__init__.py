"""
src/compliance - Regulatory compliance catalog, mapping, and exposure attribution engine.
"""

from src.compliance.catalog import (
    ControlDefinition,
    FRAMEWORK_CATALOGS,
    get_framework_controls,
    get_framework_controls_as_dicts,
    get_all_frameworks,
)
from src.compliance.mapper import ComplianceMapper
from src.compliance.scoring import ComplianceScorer

__all__ = [
    "ControlDefinition",
    "FRAMEWORK_CATALOGS",
    "get_framework_controls",
    "get_framework_controls_as_dicts",
    "get_all_frameworks",
    "ComplianceMapper",
    "ComplianceScorer",
]
