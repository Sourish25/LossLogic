"""
src/compliance/catalog.py - Formal Regulatory Compliance Catalogs.
Covers ISO/IEC 27001, NIST CSF 2.0, CIS Controls v8, RBI CSF, and SEBI CSCRF.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ControlDefinition(BaseModel):
    """Metadata and scoring weight for an individual regulatory compliance control."""
    control_id: str = Field(..., description="Unique standard control identifier (e.g. ISO-A.8.8)")
    framework: str = Field(..., description="Framework name (e.g. ISO_27001, NIST_CSF, CIS_V8, RBI_CSF, SEBI_CSCRF)")
    section: str = Field(..., description="Domain, section, or pillar name")
    title: str = Field(..., description="Title of the control")
    description: str = Field(default="", description="Detailed description of compliance requirements")
    weight: float = Field(default=1.0, ge=0.1, description="Relative audit weight in compliance scoring")
    default_remediation: str = Field(default="", description="Recommended technical mitigation action")


ISO_27001_CONTROLS: List[ControlDefinition] = [
    ControlDefinition(
        control_id="ISO-A.5.15",
        framework="ISO_27001",
        section="Organizational",
        title="Access Control",
        description="Rules to control physical and logical access to information and other associated assets.",
        weight=2.0,
        default_remediation="Implement role-based access control and principle of least privilege."
    ),
    ControlDefinition(
        control_id="ISO-A.8.2",
        framework="ISO_27001",
        section="Technological",
        title="Privileged Access Rights",
        description="Allocation and use of privileged access rights shall be restricted and managed.",
        weight=3.0,
        default_remediation="Enforce multi-factor authentication (MFA) and PAM session monitoring on privileged accounts."
    ),
    ControlDefinition(
        control_id="ISO-A.8.7",
        framework="ISO_27001",
        section="Technological",
        title="Protection Against Malware",
        description="Protection against malware shall be implemented and supported by appropriate user awareness.",
        weight=2.5,
        default_remediation="Deploy next-generation endpoint detection and response (EDR) with real-time quarantine."
    ),
    ControlDefinition(
        control_id="ISO-A.8.8",
        framework="ISO_27001",
        section="Technological",
        title="Management of Vulnerabilities",
        description="Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion.",
        weight=3.0,
        default_remediation="Implement automated vulnerability scanning and risk-prioritized patching cycles."
    ),
    ControlDefinition(
        control_id="ISO-A.8.15",
        framework="ISO_27001",
        section="Technological",
        title="Logging",
        description="Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, and reviewed.",
        weight=2.0,
        default_remediation="Forward system and security logs to a centralized, tamper-resistant SIEM."
    ),
    ControlDefinition(
        control_id="ISO-A.8.24",
        framework="ISO_27001",
        section="Technological",
        title="Use of Cryptography",
        description="Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        weight=3.0,
        default_remediation="Enforce TLS 1.3 in transit and AES-256 encryption at rest for sensitive data stores."
    ),
]

NIST_CSF_CONTROLS: List[ControlDefinition] = [
    ControlDefinition(
        control_id="PR.AA-01",
        framework="NIST_CSF",
        section="Protect",
        title="Identity Management",
        description="Identities and credentials for authorized users, services, and hardware are managed by the organization.",
        weight=2.5,
        default_remediation="Centralize identity provider directory and automate lifecycle offboarding."
    ),
    ControlDefinition(
        control_id="PR.AA-05",
        framework="NIST_CSF",
        section="Protect",
        title="Authentication & MFA",
        description="Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.",
        weight=3.0,
        default_remediation="Mandate phishing-resistant FIDO2/WebAuthn MFA across all corporate and administrative interfaces."
    ),
    ControlDefinition(
        control_id="PR.DS-01",
        framework="NIST_CSF",
        section="Protect",
        title="Data Security & Encryption",
        description="The confidentiality, integrity, and availability of data-at-rest and data-in-transit are protected.",
        weight=3.0,
        default_remediation="Implement KMS-managed encryption keys and restrict bucket/blob public ingress."
    ),
    ControlDefinition(
        control_id="PR.PS-02",
        framework="NIST_CSF",
        section="Protect",
        title="Software Vulnerabilities",
        description="Software is maintained, replaced, or retired in a timely manner according to risk-based vulnerability management.",
        weight=2.5,
        default_remediation="Automate patch orchestration for CISA KEV and high EPSS score vulnerabilities."
    ),
    ControlDefinition(
        control_id="DE.CM-01",
        framework="NIST_CSF",
        section="Detect",
        title="Continuous Monitoring",
        description="Networks and computing environments are monitored continuously to detect potential cybersecurity events.",
        weight=2.0,
        default_remediation="Implement 24x7 security monitoring with behavioral anomaly alerting."
    ),
    ControlDefinition(
        control_id="RS.MI-01",
        framework="NIST_CSF",
        section="Respond",
        title="Incident Mitigation",
        description="Incidents are contained and mitigated to prevent further damage or expansion.",
        weight=2.0,
        default_remediation="Establish automated SOAR playbooks for endpoint host containment and token revocation."
    ),
]

CIS_V8_CONTROLS: List[ControlDefinition] = [
    ControlDefinition(
        control_id="CIS-3.4",
        framework="CIS_V8",
        section="Data Protection",
        title="Enforce Data Encryption",
        description="Enforce data encryption at rest on all storage volumes containing sensitive data.",
        weight=2.5,
        default_remediation="Enable default cloud storage encryption and automated compliance checks."
    ),
    ControlDefinition(
        control_id="CIS-5.2",
        framework="CIS_V8",
        section="Account Management",
        title="MFA for Administrative Accounts",
        description="Require multi-factor authentication for all administrative access accounts.",
        weight=3.0,
        default_remediation="Enforce conditional access policies mandating hardware MFA tokens for admins."
    ),
    ControlDefinition(
        control_id="CIS-7.4",
        framework="CIS_V8",
        section="Vulnerability Management",
        title="Automated Patch Management",
        description="Perform automated vulnerability patch management on all operating systems and third-party software.",
        weight=3.0,
        default_remediation="Deploy patch automation with automated staging validation."
    ),
    ControlDefinition(
        control_id="CIS-8.2",
        framework="CIS_V8",
        section="Audit Log",
        title="Collect Audit Logs",
        description="Ensure audit logs are collected and sent to a central log management system.",
        weight=2.0,
        default_remediation="Deploy log forwarding agents and configure log retention policies."
    ),
    ControlDefinition(
        control_id="CIS-10.1",
        framework="CIS_V8",
        section="Malware Defenses",
        title="Deploy Anti-Malware Software",
        description="Deploy and maintain anti-malware software across all enterprise endpoints and servers.",
        weight=2.5,
        default_remediation="Ensure EDR sensors are active with anti-tamper safeguards enabled."
    ),
]

RBI_CSF_CONTROLS: List[ControlDefinition] = [
    ControlDefinition(
        control_id="RBI-IAM-01",
        framework="RBI_CSF",
        section="Access Control",
        title="Privileged Access Management & MFA",
        description="Mandatory PAM and hardware token MFA for all banking core systems and database access.",
        weight=3.0,
        default_remediation="Deploy enterprise PAM with just-in-time privilege granting and dual approval."
    ),
    ControlDefinition(
        control_id="RBI-VAP-01",
        framework="RBI_CSF",
        section="Vulnerability",
        title="7-Day Critical Patch SLA",
        description="Remediate all critical/high vulnerabilities on internet-facing systems within 7 calendar days.",
        weight=3.0,
        default_remediation="Enforce strict emergency change control and expedited patch deployment within 7 days."
    ),
    ControlDefinition(
        control_id="RBI-MAL-01",
        framework="RBI_CSF",
        section="Endpoint",
        title="Centralized EDR & Anti-Malware",
        description="Continuous endpoint monitoring and anti-malware coverage across all banking infrastructure.",
        weight=2.5,
        default_remediation="Ensure 100% EDR agent fleet coverage and auto-isolation on anomalous process execution."
    ),
    ControlDefinition(
        control_id="RBI-SOC-01",
        framework="RBI_CSF",
        section="SOC",
        title="24x7x365 Centralized SIEM Monitoring",
        description="Operate a dedicated 24x7 Cyber Security Operations Centre (C-SOC) for incident detection.",
        weight=2.5,
        default_remediation="Maintain continuous SOC correlation rules and integration with CERT-In incident reporting."
    ),
    ControlDefinition(
        control_id="RBI-DAT-01",
        framework="RBI_CSF",
        section="Data Protection",
        title="Payment Data Encryption & Tokenization",
        description="Protect cardholder and customer financial data using tokenization and end-to-end encryption.",
        weight=3.0,
        default_remediation="Implement HSM-backed field-level encryption for core payment transaction tables."
    ),
]

SEBI_CSCRF_CONTROLS: List[ControlDefinition] = [
    ControlDefinition(
        control_id="SEBI-WIT-01",
        framework="SEBI_CSCRF",
        section="Withstand",
        title="Zero Trust IAM & Microsegmentation",
        description="Zero-trust network architecture, micro-segmentation, and rigorous IAM for market infrastructure.",
        weight=3.0,
        default_remediation="Isolate trading core network segments and require continuous identity verification."
    ),
    ControlDefinition(
        control_id="SEBI-WIT-03",
        framework="SEBI_CSCRF",
        section="Withstand",
        title="Payload & Storage Encryption",
        description="Encrypt market order payloads, trading logs, and data stores with authenticated encryption.",
        weight=3.0,
        default_remediation="Enforce AES-GCM encryption on message queues and market data archives."
    ),
    ControlDefinition(
        control_id="SEBI-CON-01",
        framework="SEBI_CSCRF",
        section="Contain",
        title="Real-time SOC Correlation",
        description="Near real-time correlation of trading telemetry and detection of potential insider/external attacks.",
        weight=2.5,
        default_remediation="Implement high-throughput stream processing SIEM for sub-second anomaly detection."
    ),
    ControlDefinition(
        control_id="SEBI-CON-02",
        framework="SEBI_CSCRF",
        section="Contain",
        title="Automated EDR Process Isolation",
        description="Automated process isolation and quarantine on trading terminals within 15 minutes of detection.",
        weight=2.5,
        default_remediation="Configure EDR policy to auto-sever network connections on high-confidence ransomware indicators."
    ),
    ControlDefinition(
        control_id="SEBI-CON-03",
        framework="SEBI_CSCRF",
        section="Contain",
        title="48-Hour Zero-Day Remediation SLA",
        description="Mitigate zero-day or weaponized vulnerabilities in regulated market systems within 48 hours.",
        weight=3.0,
        default_remediation="Deploy virtual patching via WAF/IPS followed by verified code remediation within 48h."
    ),
]

FRAMEWORK_CATALOGS: Dict[str, List[ControlDefinition]] = {
    "ISO_27001": ISO_27001_CONTROLS,
    "NIST_CSF": NIST_CSF_CONTROLS,
    "CIS_V8": CIS_V8_CONTROLS,
    "RBI_CSF": RBI_CSF_CONTROLS,
    "SEBI_CSCRF": SEBI_CSCRF_CONTROLS,
}


def get_framework_controls(framework_name: str) -> List[ControlDefinition]:
    """Retrieve controls for a specified regulatory framework."""
    key = framework_name.upper().replace("-", "_").replace(" ", "_")
    if key in FRAMEWORK_CATALOGS:
        return FRAMEWORK_CATALOGS[key]
    for k, v in FRAMEWORK_CATALOGS.items():
        if k in key or key in k:
            return v
    return []


def get_framework_controls_as_dicts(framework_name: str) -> List[Dict[str, Any]]:
    """Retrieve controls serialized as dictionaries matching test fixtures."""
    return [c.model_dump() for c in get_framework_controls(framework_name)]


def get_all_frameworks() -> Dict[str, List[Dict[str, Any]]]:
    """Retrieve all standard regulatory framework controls serialized as dicts."""
    return {k: [c.model_dump() for c in v] for k, v in FRAMEWORK_CATALOGS.items()}
