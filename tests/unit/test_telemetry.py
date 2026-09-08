"""Comprehensive unit tests for telemetry models, adapters, normalizer, and synthetic generator."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.telemetry.adapters import CsvTelemetryAdapter, JsonTelemetryAdapter, RestTelemetryAdapter
from src.telemetry.generator import ApexEnterpriseGenerator
from src.telemetry.models import (
    CloudProvider,
    CspmFinding,
    EdrStatus,
    EdrTelemetryFinding,
    ExploitMaturity,
    IamFinding,
    NormalizedFinding,
    SeverityLevel,
    SiemAlertFinding,
    SiemAlertType,
    TelemetryDomain,
    VulnerabilityFinding,
)
from src.telemetry.normalizer import TelemetryNormalizer


# ---------------------------------------------------------------------------
# Test 1: Pydantic Data Models Across All 5 Telemetry Domains
# ---------------------------------------------------------------------------
def test_vulnerability_telemetry_model() -> None:
    """Tests Pydantic validation and field constraints for Vulnerability telemetry."""
    vuln = VulnerabilityFinding(
        finding_id="VULN-TEST-001",
        asset_id="ASSET-PROD-01",
        cve_id="CVE-2023-38606",
        title="OpenSSL Memory Corruption",
        cvss_score=9.8,
        attack_vector="NETWORK",
        exploitability_subscore=3.9,
        impact_subscore=5.9,
        epss_score=0.885,
        epss_percentile=0.985,
        exploit_maturity=ExploitMaturity.HIGH,
        cisa_kev=True,
        patch_available=True,
    )
    assert vuln.finding_id == "VULN-TEST-001"
    assert vuln.cvss_score == 9.8
    assert vuln.cvss_v3_base == 9.8
    assert vuln.epss_score == 0.885
    assert vuln.epss_probability == 0.885
    assert vuln.cisa_kev is True
    assert vuln.exploit_maturity == ExploitMaturity.HIGH

    # Out of bounds CVSS score validation
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            finding_id="VULN-ERR",
            asset_id="A1",
            cve_id="CVE-2024-0000",
            cvss_score=11.5,  # Invalid: > 10.0
            epss_score=0.5,
        )

    # Out of bounds EPSS probability validation
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            finding_id="VULN-ERR",
            asset_id="A1",
            cve_id="CVE-2024-0000",
            cvss_score=8.0,
            epss_score=1.5,  # Invalid: > 1.0
        )


def test_siem_alert_model() -> None:
    """Tests Pydantic validation for SIEM alert telemetry."""
    alert = SiemAlertFinding(
        alert_id="SIEM-ALT-001",
        asset_id="PAY-DB-01",
        rule_name="Kerberos Brute Force Attack",
        alert_count=25,
        mitre_tactic="Credential Access",
        mitre_technique="T1110.003",
        severity=SeverityLevel.HIGH,
        anomalous_login=False,
        brute_force=True,
        lateral_movement=False,
        exfiltration=False,
        confidence=0.95,
    )
    assert alert.alert_id == "SIEM-ALT-001"
    assert alert.brute_force is True
    assert alert.alert_count == 25
    assert alert.event_count_24h == 25
    assert alert.severity == SeverityLevel.HIGH
    assert alert.confidence == 0.95


def test_iam_privileged_config_model() -> None:
    """Tests Pydantic validation for IAM privileged configuration telemetry."""
    iam = IamFinding(
        identity_id="IAM-USR-99",
        asset_id="CLOUD-AWS-ROOT",
        account_name="cloud-superadmin",
        role="AdministratorAccess",
        is_admin=True,
        mfa_enabled=False,
        is_dormant=True,
        excess_privileges=True,
        inactive_days=110,
        high_risk_permissions=["*:*", "iam:PassRole"],
    )
    assert iam.identity_id == "IAM-USR-99"
    assert iam.is_admin is True
    assert iam.mfa_enabled is False
    assert iam.is_dormant is True
    assert iam.inactive_days == 110
    assert iam.dormant_days == 110
    assert iam.identity_name == "cloud-superadmin"
    assert len(iam.high_risk_permissions) == 2


def test_edr_telemetry_model() -> None:
    """Tests Pydantic validation for EDR sensor telemetry."""
    edr = EdrTelemetryFinding(
        agent_id="EDR-AGT-101",
        asset_id="CORP-NB-01",
        endpoint_hostname="cfo-laptop.internal.bank",
        agent_status=EdrStatus.DEGRADED,
        definition_version="2026.09.01",
        days_since_update=21,
        tamper_protection=True,
        active_threats_count=2,
        suspicious_process_injection=True,
        endpoint_isolated=False,
    )
    assert edr.agent_id == "EDR-AGT-101"
    assert edr.agent_status == EdrStatus.DEGRADED
    assert edr.active_threats_count == 2
    assert edr.suspicious_process_injection is True
    assert edr.days_since_update == 21


def test_cspm_cloud_misconfig_model() -> None:
    """Tests Pydantic validation for CSPM cloud posture telemetry."""
    cspm = CspmFinding(
        resource_id="arn:aws:s3:::customer-kyc-bucket",
        asset_id="RET-S3-KYC",
        cloud_provider=CloudProvider.AWS,
        service="S3",
        public_exposure=True,
        open_ports=[443],
        unencrypted_data=True,
        missing_backup=False,
        compliance_drift_count=3,
        severity=SeverityLevel.CRITICAL,
    )
    assert cspm.resource_id.startswith("arn:aws:s3")
    assert cspm.public_exposure is True
    assert cspm.unencrypted_data is True
    assert cspm.compliance_drift_count == 3
    assert cspm.severity == SeverityLevel.CRITICAL


def test_normalized_finding_model() -> None:
    """Tests Unified NormalizedFinding schema attributes."""
    norm = NormalizedFinding(
        finding_id="NORM-001",
        asset_id="ASSET-10",
        domain=TelemetryDomain.VULNERABILITY,
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.8,
        epss_score=0.92,
        cisa_kev=True,
        threat_event_frequency=0.85,
        resistance_strength=0.15,
        exploit_maturity=ExploitMaturity.WEAPONIZED,
        title="Log4j RCE",
    )
    assert norm.finding_id == "NORM-001"
    assert norm.domain == TelemetryDomain.VULNERABILITY
    assert norm.severity == SeverityLevel.CRITICAL
    assert norm.cvss_score == 9.8
    assert norm.threat_event_frequency == 0.85
    assert norm.resistance_strength == 0.15


# ---------------------------------------------------------------------------
# Test 2: Ingestion Adapters (JSON, CSV, REST)
# ---------------------------------------------------------------------------
def test_json_telemetry_adapter() -> None:
    """Tests JsonTelemetryAdapter with raw strings, lists, and wrapped structures."""
    adapter = JsonTelemetryAdapter()

    # 1. Direct JSON string of list of dicts
    json_data = """[
        {"finding_id": "V-1", "asset_id": "A-1", "cve_id": "CVE-2023-1", "cvss_score": 7.5, "epss_score": 0.2},
        {"finding_id": "V-2", "asset_id": "A-2", "cve_id": "CVE-2023-2", "cvss_score": 9.0, "epss_score": 0.8}
    ]"""
    parsed = adapter.parse(json_data)
    assert len(parsed) == 2
    assert parsed[0]["finding_id"] == "V-1"

    # Validate parsing into Pydantic models
    models = adapter.parse_to_model(json_data, VulnerabilityFinding)
    assert len(models) == 2
    assert isinstance(models[0], VulnerabilityFinding)
    assert models[1].cvss_score == 9.0

    # 2. Wrapped dictionary structure
    wrapped_data = {"findings": [{"finding_id": "V-3", "asset_id": "A-3", "cve_id": "CVE-2023-3", "cvss_score": 5.0}]}
    parsed_wrapped = adapter.parse(wrapped_data)
    assert len(parsed_wrapped) == 1
    assert parsed_wrapped[0]["finding_id"] == "V-3"

    # 3. Empty input
    assert adapter.parse("") == []
    assert adapter.parse(None) == []


def test_csv_telemetry_adapter() -> None:
    """Tests CsvTelemetryAdapter with tabular text, numeric coercion, and boolean parsing."""
    adapter = CsvTelemetryAdapter()

    csv_data = """finding_id,asset_id,cve_id,cvss_score,epss_score,cisa_kev,patch_available
VULN-CSV-1,ASSET-01,CVE-2021-44228,10.0,0.97,True,yes
VULN-CSV-2,ASSET-02,CVE-2022-22965,9.8,0.85,false,no
"""
    records = adapter.parse(csv_data)
    assert len(records) == 2

    # Check type coercion
    assert records[0]["finding_id"] == "VULN-CSV-1"
    assert records[0]["cvss_score"] == 10.0
    assert records[0]["epss_score"] == 0.97
    assert records[0]["cisa_kev"] is True
    assert records[0]["patch_available"] is True

    assert records[1]["cisa_kev"] is False
    assert records[1]["patch_available"] is False

    # Instantiate model
    models = adapter.parse_to_model(csv_data, VulnerabilityFinding)
    assert len(models) == 2
    assert models[0].cve_id == "CVE-2021-44228"
    assert models[0].cisa_kev is True


def test_rest_telemetry_adapter() -> None:
    """Tests RestTelemetryAdapter with REST envelopes, custom keys, and JSON strings."""
    adapter = RestTelemetryAdapter()

    # Standard REST envelope with 'data'
    rest_payload = {
        "status": 200,
        "total": 2,
        "data": [
            {"alert_id": "ALT-1", "asset_id": "A-1", "rule_name": "Brute Force", "alert_count": 5},
            {"alert_id": "ALT-2", "asset_id": "A-2", "rule_name": "Port Scan", "alert_count": 10},
        ],
    }
    records = adapter.parse(rest_payload)
    assert len(records) == 2
    assert records[0]["alert_id"] == "ALT-1"

    # Custom envelope key
    custom_adapter = RestTelemetryAdapter(data_key="items")
    custom_payload = {
        "items": [
            {"alert_id": "ALT-3", "asset_id": "A-3", "rule_name": "Anomalous Login", "alert_count": 1}
        ]
    }
    custom_records = custom_adapter.parse(custom_payload)
    assert len(custom_records) == 1
    assert custom_records[0]["alert_id"] == "ALT-3"


# ---------------------------------------------------------------------------
# Test 3: Telemetry Normalizer Across All 5 Domains
# ---------------------------------------------------------------------------
def test_normalizer_vulnerability() -> None:
    """Tests normalization of vulnerability findings and derivation of TEF / RS."""
    vuln = VulnerabilityFinding(
        finding_id="V-NORM-01",
        asset_id="ASSET-10",
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        attack_vector="NETWORK",
        epss_score=0.95,
        cisa_kev=True,
        exploit_maturity=ExploitMaturity.WEAPONIZED,
    )
    norm = TelemetryNormalizer.normalize_vulnerability(vuln)
    assert norm.domain == TelemetryDomain.VULNERABILITY
    assert norm.severity == SeverityLevel.CRITICAL
    assert norm.threat_event_frequency > 0.5  # High TEF due to EPSS & CISA KEV
    assert norm.resistance_strength < 0.85    # Degraded RS due to critical weaponized CVSS 10.0


def test_normalizer_siem_alert() -> None:
    """Tests normalization of SIEM alerts."""
    alert = SiemAlertFinding(
        alert_id="SIEM-NORM-01",
        asset_id="ASSET-20",
        rule_name="Exfiltration to Russian IP",
        alert_count=20,
        severity=SeverityLevel.CRITICAL,
        exfiltration=True,
        confidence=0.9,
    )
    norm = TelemetryNormalizer.normalize_siem(alert)
    assert norm.domain == TelemetryDomain.SIEM
    assert norm.severity == SeverityLevel.CRITICAL
    assert norm.threat_event_frequency > 1.0  # High frequency due to exfiltration & event count
    assert norm.resistance_strength < 0.60   # Significant degradation from exfiltration activity


def test_normalizer_iam_finding() -> None:
    """Tests normalization of IAM findings."""
    iam = IamFinding(
        identity_id="IAM-NORM-01",
        asset_id="AWS-ROOT",
        account_name="root",
        role="Admin",
        is_admin=True,
        mfa_enabled=False,
    )
    norm = TelemetryNormalizer.normalize_iam(iam)
    assert norm.domain == TelemetryDomain.IAM
    assert norm.severity == SeverityLevel.CRITICAL  # Admin without MFA is Critical
    assert norm.threat_event_frequency > 1.5
    assert norm.resistance_strength <= 0.50


def test_normalizer_edr_telemetry() -> None:
    """Tests normalization of EDR telemetry."""
    edr = EdrTelemetryFinding(
        agent_id="EDR-NORM-01",
        asset_id="HOST-10",
        endpoint_hostname="host-10.net",
        agent_status=EdrStatus.STOPPED,
        active_threats_count=1,
        suspicious_process_injection=True,
    )
    norm = TelemetryNormalizer.normalize_edr(edr)
    assert norm.domain == TelemetryDomain.EDR
    assert norm.severity == SeverityLevel.CRITICAL
    assert norm.threat_event_frequency > 2.0
    assert norm.resistance_strength < 0.15


def test_normalizer_cspm_finding() -> None:
    """Tests normalization of CSPM findings."""
    cspm = CspmFinding(
        resource_id="arn:aws:s3:::open-bucket",
        asset_id="S3-BUCKET-01",
        service="S3",
        public_exposure=True,
        unencrypted_data=True,
    )
    norm = TelemetryNormalizer.normalize_cspm(cspm)
    assert norm.domain == TelemetryDomain.CSPM
    assert norm.severity == SeverityLevel.CRITICAL
    assert norm.threat_event_frequency > 5.0
    assert norm.resistance_strength < 0.60


def test_normalizer_generic_and_batch() -> None:
    """Tests generic normalize() autodetection and normalize_batch()."""
    items = [
        {"cve_id": "CVE-2023-01", "finding_id": "V-1", "asset_id": "A-1", "cvss_score": 9.1, "epss_score": 0.5},
        {"rule_name": "Port Scanning", "alert_id": "S-1", "asset_id": "A-2", "severity": "HIGH", "confidence": 0.8},
        {"identity_name": "admin_svc", "identity_id": "I-1", "asset_id": "A-3", "is_admin": True, "mfa_enabled": True},
    ]
    normalized_list = TelemetryNormalizer.normalize_batch(items)
    assert len(normalized_list) == 3
    assert normalized_list[0].domain == TelemetryDomain.VULNERABILITY
    assert normalized_list[1].domain == TelemetryDomain.SIEM
    assert normalized_list[2].domain == TelemetryDomain.IAM


# ---------------------------------------------------------------------------
# Test 4: ApexEnterpriseGenerator Completeness
# ---------------------------------------------------------------------------
def test_synthetic_enterprise_generator_completeness() -> None:
    """
    Validates synthetic generator for ApexGlobal Financial Corp:
      - Exactly 65 assets
      - Exactly 5 Business Units: Retail Banking, Wealth Management, Payment Services,
        Cloud Infrastructure, Corporate IT
      - Telemetry across all 5 domains
      - Deterministic reproducibility
    """
    gen1 = ApexEnterpriseGenerator(seed=42)
    assets1, findings1, graph1 = gen1.generate_enterprise_dataset()

    # 1. Total asset count
    assert len(assets1) == 65

    # 2. Coverage across all 5 Business Units
    bus = {a.business_unit for a in assets1}
    expected_bus = {
        "Retail Banking",
        "Wealth Management",
        "Payment Services",
        "Cloud Infrastructure",
        "Corporate IT",
    }
    assert bus == expected_bus

    # Verify asset counts per BU
    bu_counts = {bu: sum(1 for a in assets1 if a.business_unit == bu) for bu in expected_bus}
    assert bu_counts["Payment Services"] == 15
    assert bu_counts["Retail Banking"] == 14
    assert bu_counts["Wealth Management"] == 11
    assert bu_counts["Cloud Infrastructure"] == 15
    assert bu_counts["Corporate IT"] == 10

    # 3. Findings across all 5 domains
    domains_represented = {f.domain for f in findings1}
    assert len(domains_represented) == 5
    assert TelemetryDomain.VULNERABILITY in domains_represented
    assert TelemetryDomain.SIEM in domains_represented
    assert TelemetryDomain.IAM in domains_represented
    assert TelemetryDomain.EDR in domains_represented
    assert TelemetryDomain.CSPM in domains_represented

    # 4. Dependency graph nodes and edges
    assert len(graph1.graph.nodes) >= 65
    assert len(graph1.graph.edges) > 0
    assert graph1.is_valid_dag() is True

    # 5. Deterministic reproducibility
    gen2 = ApexEnterpriseGenerator(seed=42)
    assets2, findings2, graph2 = gen2.generate_enterprise_dataset()
    assert [a.asset_id for a in assets1] == [a.asset_id for a in assets2]
    assert [f.finding_id for f in findings1] == [f.finding_id for f in findings2]
    assert [f.threat_event_frequency for f in findings1] == [f.threat_event_frequency for f in findings2]
