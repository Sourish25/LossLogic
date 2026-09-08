"""Pydantic v2 data models for the 5 security telemetry domains and unified NormalizedFinding."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class TelemetryDomain(str, Enum):
    """Supported enterprise security telemetry domains."""
    VULNERABILITY = "vulnerability"
    SIEM = "siem"
    IAM = "iam"
    EDR = "edr"
    CSPM = "cspm"


class SeverityLevel(str, Enum):
    """Finding severity levels aligned to industry standard risk taxonomies."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ExploitMaturity(str, Enum):
    """CVSS v3.1 exploit code maturity levels."""
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    WEAPONIZED = "WEAPONIZED"


class EdrStatus(str, Enum):
    """Endpoint detection and response agent operational status."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    STOPPED = "STOPPED"
    UNINSTALLED = "UNINSTALLED"


class CloudProvider(str, Enum):
    """Major enterprise cloud service providers."""
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class SiemAlertType(str, Enum):
    """SIEM alert detection classifications."""
    BRUTE_FORCE = "BRUTE_FORCE"
    ANOMALOUS_LOGIN = "ANOMALOUS_LOGIN"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MALWARE_ACTIVITY = "MALWARE_ACTIVITY"
    SUSPICIOUS_EXECUTION = "SUSPICIOUS_EXECUTION"


# ---------------------------------------------------------------------------
# Domain 1: Vulnerability Management Telemetry
# ---------------------------------------------------------------------------
class VulnerabilityFinding(BaseModel):
    """Vulnerability telemetry (CVE, CVSS v3.1, EPSS probability, exploit maturity)."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    finding_id: str = Field(..., description="Unique finding identifier (e.g. VULN-2024-001)")
    asset_id: str = Field(..., description="Target asset identifier")
    cve_id: str = Field(..., description="CVE identifier (e.g. CVE-2023-38606)")
    title: Optional[str] = Field(default=None, description="Human-readable vulnerability title")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS v3.1 Base Score")
    attack_vector: str = Field(default="NETWORK", description="Attack Vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)")
    exploitability_subscore: Optional[float] = Field(default=None, ge=0.0, le=3.9, description="CVSS exploitability")
    impact_subscore: Optional[float] = Field(default=None, ge=0.0, le=6.0, description="CVSS impact subscore")
    epss_score: float = Field(default=0.01, ge=0.0, le=1.0, description="EPSS exploit probability [0.0, 1.0]")
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="EPSS population percentile")
    exploit_maturity: ExploitMaturity = Field(
        default=ExploitMaturity.UNPROVEN, description="Exploit code maturity"
    )
    cisa_kev: bool = Field(default=False, description="Flag indicating presence on CISA KEV catalog")
    patch_available: bool = Field(default=True, description="Vendor patch availability")
    discovered_at: Optional[datetime] = Field(default=None, description="Detection timestamp")

    @property
    def cvss_v3_base(self) -> float:
        """Alias for cvss_score to maintain backwards compatibility."""
        return self.cvss_score

    @property
    def epss_probability(self) -> float:
        """Alias for epss_score."""
        return self.epss_score


# ---------------------------------------------------------------------------
# Domain 2: SIEM Alerts Telemetry
# ---------------------------------------------------------------------------
class SiemAlertFinding(BaseModel):
    """SIEM security detection alert with MITRE ATT&CK mapping and behavioral flags."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    alert_id: str = Field(..., description="Unique SIEM alert identifier")
    asset_id: str = Field(..., description="Target host or resource identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Detection timestamp"
    )
    rule_name: str = Field(..., description="Detection rule name")
    alert_count: int = Field(default=1, ge=1, description="Correlated event velocity / count in last 24h")
    mitre_tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK Tactic (e.g. Initial Access)")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK Technique ID (e.g. T1110)")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Alert severity")
    anomalous_login: bool = Field(default=False, description="Anomalous login behavior flag")
    brute_force: bool = Field(default=False, description="Password spraying or brute force flag")
    lateral_movement: bool = Field(default=False, description="Lateral movement activity flag")
    exfiltration: bool = Field(default=False, description="Data exfiltration behavior flag")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Detection rule confidence score")

    @property
    def event_count_24h(self) -> int:
        """Alias for alert_count."""
        return self.alert_count


# ---------------------------------------------------------------------------
# Domain 3: IAM Privileged Configurations Telemetry
# ---------------------------------------------------------------------------
class IamFinding(BaseModel):
    """IAM identity posture, administrator privilege, and credential hygiene."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    identity_id: str = Field(..., description="IAM identity or principal ARN/ID")
    asset_id: str = Field(..., description="Target directory, account, or resource identifier")
    account_name: str = Field(default="user", description="Account username or service principal name")
    role: str = Field(default="User", description="Assigned IAM role or group")
    identity_type: str = Field(default="USER", description="Type of identity (USER, SERVICE_ACCOUNT, ROLE)")
    is_admin: bool = Field(default=False, description="Administrator or root privilege flag")
    mfa_enabled: bool = Field(default=True, description="Multi-Factor Authentication enforcement status")
    is_dormant: bool = Field(default=False, description="Dormant account flag (>90 days without authentication)")
    excess_privileges: bool = Field(default=False, description="Excess / overprivileged permissions grant")
    inactive_days: int = Field(default=0, ge=0, description="Days elapsed since last authentication")
    high_risk_permissions: List[str] = Field(
        default_factory=list, description="List of high-risk permissions (e.g. *:*, iam:PassRole)"
    )

    @model_validator(mode="before")
    @classmethod
    def _remap_iam_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "identity_name" in data and "account_name" not in data:
                data["account_name"] = data["identity_name"]
            if "dormant_days" in data and "inactive_days" not in data:
                data["inactive_days"] = data["dormant_days"]
                if data["dormant_days"] > 90 and "is_dormant" not in data:
                    data["is_dormant"] = True
            if "excess_permissions_count" in data and "excess_privileges" not in data:
                data["excess_privileges"] = data["excess_permissions_count"] > 0
        return data

    @property
    def identity_name(self) -> str:
        return self.account_name

    @property
    def dormant_days(self) -> int:
        return self.inactive_days


# ---------------------------------------------------------------------------
# Domain 4: EDR Telemetry
# ---------------------------------------------------------------------------
class EdrTelemetryFinding(BaseModel):
    """Endpoint Detection and Response health, definitions freshness, and live threats."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    agent_id: str = Field(..., description="EDR sensor / agent unique ID")
    asset_id: str = Field(..., description="Endpoint machine or container identifier")
    endpoint_hostname: str = Field(..., description="Host FQDN or hostname")
    agent_status: EdrStatus = Field(default=EdrStatus.HEALTHY, description="EDR sensor operational health")
    definition_version: str = Field(default="1.0.0", description="Signature definition version")
    days_since_update: int = Field(default=0, ge=0, description="Days since last definition update")
    tamper_protection: bool = Field(default=True, description="Agent anti-tamper protection active")
    active_threats_count: int = Field(default=0, ge=0, description="Unquarantined active threat detections")
    suspicious_process_injection: bool = Field(
        default=False, description="Process memory injection or LSASS dumping detected"
    )
    endpoint_isolated: bool = Field(default=False, description="Network containment isolation status")


# ---------------------------------------------------------------------------
# Domain 5: CSPM Cloud Misconfigurations Telemetry
# ---------------------------------------------------------------------------
class CspmFinding(BaseModel):
    """Cloud Security Posture Management compliance violations and exposure telemetry."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    resource_id: str = Field(..., description="Cloud resource ARN or identifier")
    asset_id: str = Field(..., description="Mapped enterprise asset identifier")
    cloud_provider: CloudProvider = Field(default=CloudProvider.AWS, description="Cloud service provider")
    service: str = Field(..., description="Cloud service (e.g. S3, SecurityGroup, RDS, IAM)")
    public_exposure: bool = Field(default=False, description="Public internet exposure flag (0.0.0.0/0)")
    open_ports: List[int] = Field(default_factory=list, description="Publicly open ingress ports")
    unencrypted_data: bool = Field(default=False, description="Storage or database volume unencrypted at rest")
    missing_backup: bool = Field(default=False, description="Automated snapshot/backup disabled")
    compliance_drift_count: int = Field(default=0, ge=0, description="Number of compliance controls drifted")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Posture violation severity")


# ---------------------------------------------------------------------------
# Unified Normalized Finding Schema
# ---------------------------------------------------------------------------
class NormalizedFinding(BaseModel):
    """
    Unified standard finding schema unifying telemetry across all 5 domains.
    Provides FAIR risk parameters: Threat Event Frequency (TEF) and Resistance Strength (RS).
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    finding_id: str = Field(..., description="Unified unique finding identifier")
    asset_id: str = Field(..., description="Target asset identifier")
    domain: TelemetryDomain = Field(..., description="Source telemetry domain")
    severity: SeverityLevel = Field(..., description="Normalized risk severity")
    title: str = Field(default="", description="Human-readable title or rule name")
    description: Optional[str] = Field(default=None, description="Detailed finding explanation")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Normalized CVSS or technical severity")
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0, description="EPSS exploit probability")
    cisa_kev: bool = Field(default=False, description="CISA KEV presence flag")
    threat_event_frequency: float = Field(
        default=0.1, ge=0.0, description="FAIR Threat Event Frequency (TEF) in events/year"
    )
    resistance_strength: float = Field(
        default=0.5, ge=0.0, le=1.0, description="FAIR Resistance Strength (RS) capability [0.0, 1.0]"
    )
    exploit_maturity: ExploitMaturity = Field(
        default=ExploitMaturity.UNPROVEN, description="Exploit code maturity"
    )
    timestamp: Optional[datetime] = Field(default=None, description="Finding detection or ingestion timestamp")
    raw_payload: Optional[Dict[str, Any]] = Field(
        default=None, description="Original raw domain telemetry payload"
    )
