"""Enterprise configuration, currency parameters, data sensitivity multipliers, and regulatory constants."""

from enum import Enum
from typing import Dict
from pydantic import BaseModel, Field


class DataSensitivityTier(str, Enum):
    """Classification tiers for enterprise data assets."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class EnvironmentTier(str, Enum):
    """Operational deployment environments."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    SANDBOX = "sandbox"


# Currency conversion parameters
USD_TO_INR_RATE: float = 83.5
INR_TO_USD_RATE: float = 1.0 / USD_TO_INR_RATE

# Data sensitivity multipliers for secondary loss and regulatory fine exposures
DATA_SENSITIVITY_MULTIPLIERS: Dict[str, float] = {
    DataSensitivityTier.PUBLIC.value: 0.2,
    DataSensitivityTier.INTERNAL.value: 0.5,
    DataSensitivityTier.CONFIDENTIAL.value: 1.0,
    DataSensitivityTier.RESTRICTED.value: 2.5,
}

# Operational environment risk multipliers
ENVIRONMENT_MULTIPLIERS: Dict[str, float] = {
    EnvironmentTier.PRODUCTION.value: 1.0,
    EnvironmentTier.STAGING.value: 0.3,
    EnvironmentTier.DEVELOPMENT.value: 0.1,
    EnvironmentTier.SANDBOX.value: 0.005,
}

# Regulatory & financial exposure constants
BASE_REGULATORY_FINE: float = 500_000.0          # Base statutory fine per major incident (USD)
DEFAULT_MTTR_HOURS: float = 24.0                 # Mean Time to Recover for business interruptions
MAX_ENTERPRISE_VALUATION: float = 100_000_000.0  # Ceiling for normalizing financial asset valuation
DEFAULT_CURRENCY: str = "USD"


def usd_to_inr(amount_usd: float) -> float:
    """Convert USD amount to INR."""
    return amount_usd * USD_TO_INR_RATE


def inr_to_usd(amount_inr: float) -> float:
    """Convert INR amount to USD."""
    return amount_inr * INR_TO_USD_RATE


class EnterpriseSettings(BaseModel):
    """Global enterprise risk quantification configuration."""
    usd_to_inr: float = Field(default=USD_TO_INR_RATE, description="USD to INR exchange rate")
    base_regulatory_fine: float = Field(default=BASE_REGULATORY_FINE, description="Base regulatory fine in USD")
    default_mttr_hours: float = Field(default=DEFAULT_MTTR_HOURS, description="Default MTTR in hours")
    max_enterprise_valuation: float = Field(
        default=MAX_ENTERPRISE_VALUATION, description="Valuation normalization ceiling in USD"
    )
    data_sensitivity_multipliers: Dict[str, float] = Field(
        default_factory=lambda: dict(DATA_SENSITIVITY_MULTIPLIERS)
    )
    environment_multipliers: Dict[str, float] = Field(
        default_factory=lambda: dict(ENVIRONMENT_MULTIPLIERS)
    )


# Singleton enterprise settings instance
settings = EnterpriseSettings()
