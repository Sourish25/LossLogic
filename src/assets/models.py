"""Asset and business service schemas for enterprise criticality modeling."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from src.config import DataSensitivityTier, EnvironmentTier


class AssetType(str, Enum):
    """Enterprise technical asset categories."""
    DATABASE = "database"
    SERVER = "server"
    CONTAINER = "container"
    S3_BUCKET = "s3_bucket"
    ENDPOINT = "endpoint"
    API_GATEWAY = "api_gateway"


class BusinessService(BaseModel):
    """Enterprise business process or revenue-generating customer service."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    service_id: str = Field(..., description="Unique business service ID (e.g. SVC-PAYMENTS)")
    name: str = Field(..., description="Human-readable service name")
    business_unit: str = Field(..., description="Owning business unit")
    revenue_per_hour_downtime: float = Field(
        ..., ge=0.0, description="Gross revenue lost per hour of service outage (USD)"
    )
    criticality: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Business criticality tier [0.0, 1.0]"
    )
    description: Optional[str] = Field(default=None, description="Service description")


class AssetRecord(BaseModel):
    """Comprehensive enterprise asset record incorporating operational and financial parameters."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    asset_id: str = Field(..., description="Unique technical asset identifier")
    name: str = Field(..., description="Hostname, container name, or resource label")
    business_unit: str = Field(..., description="Associated business unit")
    environment: EnvironmentTier = Field(
        default=EnvironmentTier.PRODUCTION, description="Deployment environment tier"
    )
    asset_type: AssetType = Field(default=AssetType.SERVER, description="Asset classification")
    data_sensitivity_tier: DataSensitivityTier = Field(
        default=DataSensitivityTier.INTERNAL, description="Data classification level"
    )
    replacement_cost: float = Field(
        default=10_000.0, ge=0.0, description="Cost to re-provision and restore asset (USD)"
    )
    downtime_cost_per_hour: float = Field(
        default=0.0, ge=0.0, description="Direct hourly downtime cost of this asset (USD)"
    )
    dependent_services: List[str] = Field(
        default_factory=list, description="IDs of BusinessServices directly or indirectly dependent on this asset"
    )
    financial_asset_valuation: float = Field(
        default=0.0, ge=0.0, description="Total financial valuation (replacement + MTTR downtime + regulatory fines)"
    )
    asset_criticality_score: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Calculated Asset Criticality Score (ACS) [0.0, 1.0]"
    )
    ip_address: Optional[str] = Field(default=None, description="IP address")
    hostname: Optional[str] = Field(default=None, description="FQDN")
    tags: Dict[str, str] = Field(default_factory=dict, description="Custom operational tags")


class DependencyEdge(BaseModel):
    """Directed dependency relation indicating dependent -> provider."""
    model_config = ConfigDict(extra="ignore")

    source_id: str = Field(..., description="Dependent node ID (Service or Asset)")
    target_id: str = Field(..., description="Provider node ID that source depends upon")
    dependency_type: str = Field(default="DEPENDS_ON", description="Dependency relationship type")
