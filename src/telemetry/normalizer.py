"""Telemetry normalizer: Transforms multi-domain security events into unified NormalizedFinding models."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
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
    TelemetryDomain,
    VulnerabilityFinding,
)

# Sensitive ingress ports commonly targeted by automated botnets
SENSITIVE_PORTS = {21, 22, 23, 25, 3389, 445, 1433, 1521, 3306, 5432, 6379, 8080, 9200, 27017}

EXPLOIT_MATURITY_FACTORS = {
    ExploitMaturity.UNPROVEN: 0.2,
    ExploitMaturity.PROOF_OF_CONCEPT: 0.4,
    ExploitMaturity.FUNCTIONAL: 0.6,
    ExploitMaturity.HIGH: 0.8,
    ExploitMaturity.WEAPONIZED: 1.0,
}


class TelemetryNormalizer:
    """Normalizes domain-specific telemetry payloads into unified NormalizedFinding records."""

    @classmethod
    def normalize_vulnerability(
        cls, finding: Union[VulnerabilityFinding, Dict[str, Any]]
    ) -> NormalizedFinding:
        """Normalizes a vulnerability scan finding."""
        if isinstance(finding, dict):
            # Handle potential cvss_score alias
            if "cvss_score" not in finding and "cvss_v3_base" in finding:
                finding["cvss_score"] = finding["cvss_v3_base"]
            v = VulnerabilityFinding.model_validate(finding)
        else:
            v = finding

        # FAIR parameter derivations:
        # CF_base: 1.0 for network attack vector, 0.3 for local
        cf_base = 1.0 if v.attack_vector.upper() == "NETWORK" else 0.3
        # Probability of Action (PoA) driven by EPSS score and CISA KEV
        poa = min(1.0, 0.05 + 0.65 * v.epss_score + (0.30 if v.cisa_kev else 0.0))
        tef = round(cf_base * poa, 4)

        # Resistance Strength (RS) degradation
        exploit_factor = EXPLOIT_MATURITY_FACTORS.get(v.exploit_maturity, 0.2)
        d_vuln = 0.12 * (v.cvss_score / 10.0) * exploit_factor
        rs_base = 0.85
        rs = round(max(0.02, min(0.99, rs_base * (1.0 - d_vuln))), 4)

        # Map CVSS score to standard SeverityLevel
        if v.cvss_score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif v.cvss_score >= 7.0:
            severity = SeverityLevel.HIGH
        elif v.cvss_score >= 4.0:
            severity = SeverityLevel.MEDIUM
        elif v.cvss_score > 0.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.INFORMATIONAL

        title = v.title or f"{v.cve_id} ({severity.value})"
        desc = f"Vulnerability {v.cve_id} on {v.asset_id}, CVSS: {v.cvss_score}, EPSS: {v.epss_score}"

        return NormalizedFinding(
            finding_id=v.finding_id,
            asset_id=v.asset_id,
            domain=TelemetryDomain.VULNERABILITY,
            severity=severity,
            title=title,
            description=desc,
            cvss_score=v.cvss_score,
            epss_score=v.epss_score,
            cisa_kev=v.cisa_kev,
            threat_event_frequency=tef,
            resistance_strength=rs,
            exploit_maturity=v.exploit_maturity,
            timestamp=v.discovered_at or datetime.now(timezone.utc),
            raw_payload=v.model_dump(),
        )

    @classmethod
    def normalize_siem(
        cls, finding: Union[SiemAlertFinding, Dict[str, Any]]
    ) -> NormalizedFinding:
        """Normalizes a SIEM alert."""
        if isinstance(finding, dict):
            if "alert_count" not in finding and "event_count_24h" in finding:
                finding["alert_count"] = finding["event_count_24h"]
            s = SiemAlertFinding.model_validate(finding)
        else:
            s = finding

        # CF based on event velocity
        cf = 0.5 + 0.15 * min(s.alert_count, 50)
        # PoA based on behavioral indicators
        if s.exfiltration:
            poa = 0.90
        elif s.lateral_movement:
            poa = 0.80
        elif s.brute_force:
            poa = 0.60
        elif s.anomalous_login:
            poa = 0.50
        else:
            poa = 0.30

        tef = round(cf * poa * s.confidence, 4)

        # Resistance strength degraded by attack progression
        deg = 0.0
        if s.exfiltration:
            deg += 0.45
        if s.lateral_movement:
            deg += 0.35
        if s.brute_force:
            deg += 0.20
        if s.anomalous_login:
            deg += 0.15
        deg = min(0.95, deg)

        rs = round(max(0.02, min(0.99, 0.85 * (1.0 - deg))), 4)

        # Approximate CVSS-like technical severity scale [0, 10]
        severity_cvss_map = {
            SeverityLevel.CRITICAL: 9.5,
            SeverityLevel.HIGH: 7.8,
            SeverityLevel.MEDIUM: 5.5,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFORMATIONAL: 1.0,
        }
        cvss_equiv = severity_cvss_map.get(s.severity, 5.0)

        return NormalizedFinding(
            finding_id=s.alert_id,
            asset_id=s.asset_id,
            domain=TelemetryDomain.SIEM,
            severity=s.severity,
            title=s.rule_name,
            description=(
                f"SIEM Alert: {s.rule_name}, count: {s.alert_count}, "
                f"tactic: {s.mitre_tactic or 'N/A'}, technique: {s.mitre_technique or 'N/A'}"
            ),
            cvss_score=cvss_equiv,
            epss_score=min(1.0, poa),
            cisa_kev=False,
            threat_event_frequency=tef,
            resistance_strength=rs,
            exploit_maturity=ExploitMaturity.FUNCTIONAL if (s.lateral_movement or s.exfiltration) else ExploitMaturity.PROOF_OF_CONCEPT,
            timestamp=s.timestamp,
            raw_payload=s.model_dump(),
        )

    @classmethod
    def normalize_iam(
        cls, finding: Union[IamFinding, Dict[str, Any]]
    ) -> NormalizedFinding:
        """Normalizes an IAM privilege finding."""
        i = IamFinding.model_validate(finding) if isinstance(finding, dict) else finding

        # Baseline exposure
        if i.is_admin and not i.mfa_enabled:
            cf = 2.5
            poa = 0.85
            severity = SeverityLevel.CRITICAL
            cvss_equiv = 9.2
        elif i.is_admin and i.excess_privileges:
            cf = 1.8
            poa = 0.65
            severity = SeverityLevel.HIGH
            cvss_equiv = 7.5
        elif i.is_dormant and i.is_admin:
            cf = 1.5
            poa = 0.55
            severity = SeverityLevel.HIGH
            cvss_equiv = 7.0
        elif i.is_dormant or i.excess_privileges:
            cf = 1.0
            poa = 0.40
            severity = SeverityLevel.MEDIUM
            cvss_equiv = 5.0
        else:
            cf = 0.5
            poa = 0.20
            severity = SeverityLevel.LOW
            cvss_equiv = 2.5

        tef = round(cf * poa, 4)

        # Resistance strength
        deg = 0.0
        if i.is_admin and not i.mfa_enabled:
            deg += 0.45
        if i.excess_privileges:
            deg += 0.25
        if i.is_dormant:
            deg += 0.15
        deg = min(0.95, deg)

        rs = round(max(0.02, min(0.99, 0.85 * (1.0 - deg))), 4)

        title = f"IAM Posture: {i.identity_name} ({i.role})"
        desc = (
            f"IAM identity {i.identity_name}: admin={i.is_admin}, mfa={i.mfa_enabled}, "
            f"dormant={i.is_dormant}, inactive_days={i.inactive_days}"
        )

        return NormalizedFinding(
            finding_id=i.identity_id,
            asset_id=i.asset_id,
            domain=TelemetryDomain.IAM,
            severity=severity,
            title=title,
            description=desc,
            cvss_score=cvss_equiv,
            epss_score=min(1.0, poa),
            cisa_kev=False,
            threat_event_frequency=tef,
            resistance_strength=rs,
            exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
            timestamp=datetime.now(timezone.utc),
            raw_payload=i.model_dump(),
        )

    @classmethod
    def normalize_edr(
        cls, finding: Union[EdrTelemetryFinding, Dict[str, Any]]
    ) -> NormalizedFinding:
        """Normalizes an EDR agent health and detection finding."""
        e = EdrTelemetryFinding.model_validate(finding) if isinstance(finding, dict) else finding

        # Baseline resistance
        if e.agent_status == EdrStatus.HEALTHY:
            rs_base = 0.90
        elif e.agent_status == EdrStatus.DEGRADED:
            rs_base = 0.50
        else:
            rs_base = 0.15

        # Degrade for threats, injections, old definitions
        deg = 0.0
        if e.active_threats_count > 0:
            deg += 0.40
        if e.suspicious_process_injection:
            deg += 0.35
        if e.days_since_update > 14:
            deg += 0.15
        if not e.tamper_protection:
            deg += 0.10
        deg = min(0.95, deg)

        rs = round(max(0.02, min(0.99, rs_base * (1.0 - deg))), 4)

        # Threat frequency
        if e.suspicious_process_injection or e.active_threats_count > 0:
            cf = 2.0 + 1.5 * e.active_threats_count
            poa = 0.85
            severity = SeverityLevel.CRITICAL
            cvss_equiv = 9.4
        elif e.agent_status in (EdrStatus.STOPPED, EdrStatus.UNINSTALLED):
            cf = 1.5
            poa = 0.65
            severity = SeverityLevel.HIGH
            cvss_equiv = 8.0
        elif e.agent_status == EdrStatus.DEGRADED or e.days_since_update > 14:
            cf = 1.0
            poa = 0.40
            severity = SeverityLevel.MEDIUM
            cvss_equiv = 5.5
        else:
            cf = 0.3
            poa = 0.10
            severity = SeverityLevel.LOW
            cvss_equiv = 2.0

        tef = round(cf * poa, 4)
        title = f"EDR Telemetry: {e.endpoint_hostname} ({e.agent_status.value})"
        desc = (
            f"EDR Host {e.endpoint_hostname}: status={e.agent_status.value}, "
            f"active_threats={e.active_threats_count}, injection={e.suspicious_process_injection}"
        )

        return NormalizedFinding(
            finding_id=e.agent_id,
            asset_id=e.asset_id,
            domain=TelemetryDomain.EDR,
            severity=severity,
            title=title,
            description=desc,
            cvss_score=cvss_equiv,
            epss_score=min(1.0, poa),
            cisa_kev=False,
            threat_event_frequency=tef,
            resistance_strength=rs,
            exploit_maturity=ExploitMaturity.HIGH if e.suspicious_process_injection else ExploitMaturity.PROOF_OF_CONCEPT,
            timestamp=datetime.now(timezone.utc),
            raw_payload=e.model_dump(),
        )

    @classmethod
    def normalize_cspm(
        cls, finding: Union[CspmFinding, Dict[str, Any]]
    ) -> NormalizedFinding:
        """Normalizes a CSPM cloud configuration finding."""
        c = CspmFinding.model_validate(finding) if isinstance(finding, dict) else finding

        has_sensitive_port = any(p in SENSITIVE_PORTS for p in c.open_ports)

        if c.public_exposure and (c.unencrypted_data or has_sensitive_port):
            severity = SeverityLevel.CRITICAL
            cvss_equiv = 9.3
            cf = 10.0
            poa = 0.80
        elif c.public_exposure:
            severity = SeverityLevel.HIGH
            cvss_equiv = 7.5
            cf = 5.0
            poa = 0.65
        elif c.unencrypted_data:
            severity = SeverityLevel.HIGH
            cvss_equiv = 7.0
            cf = 1.5
            poa = 0.50
        elif c.missing_backup or c.compliance_drift_count > 3:
            severity = SeverityLevel.MEDIUM
            cvss_equiv = 5.0
            cf = 1.0
            poa = 0.35
        else:
            severity = c.severity
            cvss_equiv = 3.5
            cf = 0.5
            poa = 0.20

        tef = round(cf * poa, 4)

        deg = 0.0
        if c.public_exposure:
            deg += 0.35
        if c.unencrypted_data:
            deg += 0.30
        if c.missing_backup:
            deg += 0.20
        if c.compliance_drift_count > 0:
            deg += min(0.30, 0.05 * c.compliance_drift_count)
        deg = min(0.95, deg)

        rs = round(max(0.02, min(0.99, 0.85 * (1.0 - deg))), 4)

        title = f"CSPM Misconfiguration: {c.service} ({c.cloud_provider.value})"
        desc = (
            f"Resource {c.resource_id}: public={c.public_exposure}, open_ports={c.open_ports}, "
            f"unencrypted={c.unencrypted_data}, drift={c.compliance_drift_count}"
        )

        return NormalizedFinding(
            finding_id=c.resource_id,
            asset_id=c.asset_id,
            domain=TelemetryDomain.CSPM,
            severity=severity,
            title=title,
            description=desc,
            cvss_score=cvss_equiv,
            epss_score=min(1.0, poa),
            cisa_kev=False,
            threat_event_frequency=tef,
            resistance_strength=rs,
            exploit_maturity=ExploitMaturity.FUNCTIONAL if c.public_exposure else ExploitMaturity.PROOF_OF_CONCEPT,
            timestamp=datetime.now(timezone.utc),
            raw_payload=c.model_dump(),
        )

    @classmethod
    def normalize(
        cls,
        item: Any,
        domain: Optional[TelemetryDomain] = None,
    ) -> NormalizedFinding:
        """
        Generic normalization method detecting domain from object type, domain argument,
        or dictionary domain key.
        """
        if isinstance(item, NormalizedFinding):
            return item

        # Object type detection
        if isinstance(item, VulnerabilityFinding):
            return cls.normalize_vulnerability(item)
        elif isinstance(item, SiemAlertFinding):
            return cls.normalize_siem(item)
        elif isinstance(item, IamFinding):
            return cls.normalize_iam(item)
        elif isinstance(item, EdrTelemetryFinding):
            return cls.normalize_edr(item)
        elif isinstance(item, CspmFinding):
            return cls.normalize_cspm(item)

        if isinstance(item, dict):
            # Explicit domain passed
            effective_domain = domain
            if not effective_domain and "domain" in item:
                effective_domain = TelemetryDomain(item["domain"])

            # Infer from signature keys
            if not effective_domain:
                if "cve_id" in item or "cvss_score" in item or "cvss_v3_base" in item:
                    effective_domain = TelemetryDomain.VULNERABILITY
                elif "rule_name" in item or "alert_type" in item:
                    effective_domain = TelemetryDomain.SIEM
                elif "identity_name" in item or "mfa_enabled" in item or "role" in item:
                    effective_domain = TelemetryDomain.IAM
                elif "agent_status" in item or "tamper_protection" in item or "endpoint_hostname" in item:
                    effective_domain = TelemetryDomain.EDR
                elif "cloud_provider" in item or "public_exposure" in item or "resource_id" in item:
                    effective_domain = TelemetryDomain.CSPM

            if effective_domain == TelemetryDomain.VULNERABILITY:
                return cls.normalize_vulnerability(item)
            elif effective_domain == TelemetryDomain.SIEM:
                return cls.normalize_siem(item)
            elif effective_domain == TelemetryDomain.IAM:
                return cls.normalize_iam(item)
            elif effective_domain == TelemetryDomain.EDR:
                return cls.normalize_edr(item)
            elif effective_domain == TelemetryDomain.CSPM:
                return cls.normalize_cspm(item)

        raise ValueError(f"Unable to normalize item of type {type(item)} with domain {domain}")

    @classmethod
    def normalize_batch(
        cls,
        items: List[Any],
        domain: Optional[TelemetryDomain] = None,
    ) -> List[NormalizedFinding]:
        """Normalizes a list of items across one or multiple domains."""
        return [cls.normalize(item, domain) for item in items]
