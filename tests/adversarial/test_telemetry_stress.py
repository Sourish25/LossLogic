"""
Adversarial Stress Test Suite for Milestone 1: Telemetry Ingestion & Asset Criticality Engine.

Probing:
1. Malformed, corrupted, and partial telemetry feeds (JSON, CSV, REST).
2. Extreme boundary conditions: CVSS 0.0/10.0, EPSS 0.0/1.0, 0 alerts, 100,000 alerts.
3. Ingestion performance and memory footprint with 1,000+ findings across 5 domains.
4. Mathematical invariants, dynamic impact ratios, and exception resilience.
"""

import csv
import io
import json
import math
import time
import tracemalloc
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from src.assets.graph import EnterpriseDependencyGraph
from src.assets.models import AssetRecord, BusinessService, DataSensitivityTier, EnvironmentTier
from src.assets.scoring import (
    calculate_asset_criticality_score,
    calculate_asset_financial_valuation,
    calculate_contextual_severity,
    calculate_finding_impact,
)
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


# ===========================================================================
# 1. Malformed & Corrupted Telemetry Feeds
# ===========================================================================
class TestMalformedTelemetryFeeds:
    """Stress-test ingestion adapters with corrupted, partial, and hostile payloads."""

    def test_json_adapter_corrupted_syntax(self):
        """Probes JSON adapter with syntactically corrupted feeds."""
        adapter = JsonTelemetryAdapter()

        # Truncated JSON
        with pytest.raises(json.JSONDecodeError):
            adapter.parse('{"finding_id": "VULN-001", "cvss_score":')

        # Unquoted keys and trailing commas
        with pytest.raises(json.JSONDecodeError):
            adapter.parse('{finding_id: "VULN-001",}')

        # Garbage binary/non-JSON text
        with pytest.raises(json.JSONDecodeError):
            adapter.parse("<<<NOT_JSON_DATA>>>")

    def test_json_adapter_null_and_empty_inputs(self):
        """Probes JSON adapter with empty, None, and whitespace inputs."""
        adapter = JsonTelemetryAdapter()
        assert adapter.parse(None) == []
        assert adapter.parse("") == []
        assert adapter.parse("   ") == []
        assert adapter.parse(b"") == []
        assert adapter.parse(b"  \n\t  ") == []
        assert adapter.parse("[]") == []

    def test_json_adapter_hostile_types(self):
        """Probes JSON adapter with unexpected data types."""
        adapter = JsonTelemetryAdapter()
        with pytest.raises(ValueError, match="Unexpected JSON payload type"):
            adapter.parse(12345)
        with pytest.raises(ValueError, match="Unexpected JSON payload type"):
            adapter.parse(True)

    def test_json_adapter_dirty_list_filtering(self):
        """Probes JSON adapter with lists containing non-dictionary elements."""
        adapter = JsonTelemetryAdapter()
        dirty_list = [
            {"finding_id": "V1", "cvss_score": 7.5},
            "corrupted_string_item",
            12345,
            None,
            [1, 2, 3],
            {"finding_id": "V2", "cvss_score": 9.0},
        ]
        parsed = adapter.parse(dirty_list)
        # Should gracefully filter out all non-dict primitives
        assert len(parsed) == 2
        assert parsed[0]["finding_id"] == "V1"
        assert parsed[1]["finding_id"] == "V2"

    def test_json_adapter_envelope_unwrapping(self):
        """Probes JSON adapter with varied wrapper keys."""
        adapter = JsonTelemetryAdapter()
        for key in ("findings", "alerts", "data", "records", "items", "results"):
            wrapped = {key: [{"finding_id": f"ID-{key}", "score": 5.0}]}
            parsed = adapter.parse(wrapped)
            assert len(parsed) == 1
            assert parsed[0]["finding_id"] == f"ID-{key}"

    def test_csv_adapter_corrupted_and_ragged_rows(self):
        """Probes CSV adapter with malformed CSV text."""
        adapter = CsvTelemetryAdapter()

        # Empty and None
        assert adapter.parse(None) == []
        assert adapter.parse("") == []
        assert adapter.parse("   ") == []

        # Headers only, no rows
        header_only = "finding_id,asset_id,cve_id,cvss_score\n"
        assert adapter.parse(header_only) == []

        # Ragged rows: missing values
        ragged_csv = (
            "finding_id,asset_id,cve_id,cvss_score\n"
            "V1,ASSET-1\n"
            "V2,ASSET-2,CVE-2024-1111,8.5\n"
        )
        parsed = adapter.parse(ragged_csv)
        assert len(parsed) == 2
        assert parsed[0]["finding_id"] == "V1"
        assert parsed[0]["cve_id"] is None or parsed[0]["cve_id"] == ""
        assert parsed[1]["cvss_score"] == 8.5

    def test_csv_adapter_coercion_stress(self):
        """Probes CSV type coercion with extreme boolean and list representations."""
        adapter = CsvTelemetryAdapter()
        # Note: In RFC 4180 CSV, fields with commas must be quoted: "\"[22, 443, 8080]\""
        csv_data = (
            'id,flag_true,flag_false,num_int,num_float,str_null,arr_brackets,arr_semicolons\n'
            '1,yes,NO,-42,3.14159,null,"[22, 443, 8080]",a;b;c\n'
            '2,t,f,0,-0.5,N/A,[80;443],single\n'
        )
        records = adapter.parse(csv_data)
        assert len(records) == 2

        # Row 1: Quoted brackets with commas
        r1 = records[0]
        assert r1["flag_true"] is True
        assert r1["flag_false"] is False
        assert r1["num_int"] == -42
        assert isinstance(r1["num_float"], float) and math.isclose(r1["num_float"], 3.14159)
        assert r1["str_null"] is None
        assert r1["arr_brackets"] == [22, 443, 8080]
        assert r1["arr_semicolons"] == ["a", "b", "c"]

        # Row 2: Brackets with semicolons
        r2 = records[1]
        assert r2["flag_true"] is True
        assert r2["flag_false"] is False
        assert r2["num_int"] == 0
        assert r2["num_float"] == -0.5
        assert r2["str_null"] is None
        assert r2["arr_brackets"] == [80, 443]

    def test_rest_adapter_edge_envelopes(self):
        """Probes REST adapter with edge-case response envelopes and custom data keys."""
        # Standard candidate keys
        rest_adapter = RestTelemetryAdapter()
        resp = {"data": [{"alert_id": "A1"}], "page": 1, "total": 100}
        assert len(rest_adapter.parse(resp)) == 1

        # Explicit custom data_key
        custom_adapter = RestTelemetryAdapter(data_key="custom_findings")
        resp_custom = {"custom_findings": [{"finding_id": "CF1"}, {"finding_id": "CF2"}]}
        assert len(custom_adapter.parse(resp_custom)) == 2

        # Missing data_key fallback
        resp_fallback = {"items": [{"finding_id": "FALLBACK1"}]}
        assert len(custom_adapter.parse(resp_fallback)) == 1

        # Invalid REST type
        with pytest.raises(ValueError, match="Cannot parse REST payload"):
            rest_adapter.parse(9999)

    def test_normalizer_partial_dict_rejection(self):
        """Verifies that TelemetryNormalizer rejects incomplete dict payloads via ValidationError."""
        # Missing asset_id and cve_id in vulnerability
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_vulnerability({"finding_id": "V1", "cvss_score": 5.0})

        # Missing alert_id and rule_name in SIEM
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_siem({"asset_id": "AS1", "alert_count": 5})

        # Missing identity_id in IAM
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_iam({"asset_id": "AS1", "role": "Admin"})

        # Missing agent_id and endpoint_hostname in EDR
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_edr({"asset_id": "AS1"})

        # Missing resource_id and service in CSPM
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_cspm({"asset_id": "AS1"})

    def test_normalizer_unknown_domain_rejection(self):
        """Verifies that unknown or uninferrable dictionaries raise ValueError."""
        with pytest.raises(ValueError, match="Unable to normalize item"):
            TelemetryNormalizer.normalize({"unrelated_field_1": 123, "unrelated_field_2": "abc"})


# ===========================================================================
# 2. Extreme Boundary Values: CVSS, EPSS, Alert Counts
# ===========================================================================
class TestBoundaryAndExtremeValues:
    """Stress-test numerical boundaries, saturation points, and schema constraints."""

    def test_cvss_minimal_boundary_zero(self):
        """Boundary: CVSS = 0.0 (Minimal technical severity, informational)."""
        vuln = VulnerabilityFinding(
            finding_id="VULN-ZERO",
            asset_id="ASSET-PROD-01",
            cve_id="CVE-2024-0000",
            cvss_score=0.0,
            epss_score=0.0,
            cisa_kev=False,
            attack_vector="NETWORK",
        )
        norm = TelemetryNormalizer.normalize_vulnerability(vuln)
        assert norm.cvss_score == 0.0
        assert norm.severity == SeverityLevel.INFORMATIONAL
        assert norm.resistance_strength == 0.85
        assert norm.threat_event_frequency == 0.05

        # Financial impact of CVSS 0.0 finding must be exactly 0.0
        asset = AssetRecord(
            asset_id="ASSET-PROD-01",
            name="Prod Server",
            business_unit="Payment Services",
            replacement_cost=500000.0,
            downtime_cost_per_hour=10000.0,
            environment=EnvironmentTier.PRODUCTION,
            data_sensitivity_tier=DataSensitivityTier.CONFIDENTIAL,
        )
        impact = calculate_finding_impact(norm, asset)
        assert impact == 0.0

    def test_cvss_maximal_boundary_ten(self):
        """Boundary: CVSS = 10.0 (Maximal technical severity, critical)."""
        vuln = VulnerabilityFinding(
            finding_id="VULN-MAX",
            asset_id="ASSET-PROD-01",
            cve_id="CVE-2024-9999",
            cvss_score=10.0,
            epss_score=1.0,
            cisa_kev=True,
            attack_vector="NETWORK",
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        )
        norm = TelemetryNormalizer.normalize_vulnerability(vuln)
        assert norm.cvss_score == 10.0
        assert norm.severity == SeverityLevel.CRITICAL
        # weaponized exploit factor = 1.0; d_vuln = 0.12 * 1.0 * 1.0 = 0.12; rs = 0.85 * (1 - 0.12) = 0.748
        assert math.isclose(norm.resistance_strength, 0.748, rel_tol=1e-3)
        # PoA = min(1.0, 0.05 + 0.65*1.0 + 0.30) = 1.0; tef = 1.0 * 1.0 = 1.0
        assert norm.threat_event_frequency == 1.0

        asset = AssetRecord(
            asset_id="ASSET-PROD-01",
            name="Prod Server",
            business_unit="Payment Services",
            replacement_cost=500000.0,
            downtime_cost_per_hour=10000.0,
            environment=EnvironmentTier.PRODUCTION,
            data_sensitivity_tier=DataSensitivityTier.RESTRICTED,
        )
        impact = calculate_finding_impact(norm, asset)
        assert impact > 0.0

    def test_cvss_out_of_bounds_rejection(self):
        """Boundary: CVSS < 0.0 or CVSS > 10.0 must be rejected by Pydantic."""
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                finding_id="V-NEG", asset_id="A1", cve_id="CVE-1", cvss_score=-0.1
            )
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                finding_id="V-HIGH", asset_id="A1", cve_id="CVE-1", cvss_score=10.01
            )

    def test_epss_minimal_and_maximal_boundaries(self):
        """Boundary: EPSS = 0.0 and EPSS = 1.0."""
        # EPSS = 0.0
        v_low = VulnerabilityFinding(
            finding_id="V-EPSS-0", asset_id="A1", cve_id="CVE-1", cvss_score=5.0, epss_score=0.0
        )
        n_low = TelemetryNormalizer.normalize_vulnerability(v_low)
        assert n_low.epss_score == 0.0
        assert n_low.threat_event_frequency == 0.05  # baseline PoA = 0.05

        # EPSS = 1.0
        v_high = VulnerabilityFinding(
            finding_id="V-EPSS-1", asset_id="A1", cve_id="CVE-2", cvss_score=5.0, epss_score=1.0
        )
        n_high = TelemetryNormalizer.normalize_vulnerability(v_high)
        assert n_high.epss_score == 1.0
        assert math.isclose(n_high.threat_event_frequency, 0.70, rel_tol=1e-3)

    def test_epss_out_of_bounds_rejection(self):
        """Boundary: EPSS < 0.0 or EPSS > 1.0 must be rejected."""
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                finding_id="V-EPSS-NEG", asset_id="A1", cve_id="CVE-1", cvss_score=5.0, epss_score=-0.01
            )
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                finding_id="V-EPSS-OVER", asset_id="A1", cve_id="CVE-1", cvss_score=5.0, epss_score=1.001
            )

    def test_empty_feed_zero_alerts_boundary(self):
        """Boundary: 0 alerts in telemetry stream across all adapters."""
        json_adapter = JsonTelemetryAdapter()
        csv_adapter = CsvTelemetryAdapter()
        rest_adapter = RestTelemetryAdapter()

        assert json_adapter.parse("[]") == []
        assert json_adapter.parse('{"alerts": []}') == []
        assert csv_adapter.parse("alert_id,asset_id,rule_name,alert_count\n") == []
        assert rest_adapter.parse({"alerts": []}) == []

        norm_batch = TelemetryNormalizer.normalize_batch([])
        assert norm_batch == []

    def test_siem_alert_count_zero_enforces_schema_contract(self):
        """
        Boundary: Probes SIEM model with alert_count = 0.
        Empirical finding: SiemAlertFinding specifies ge=1, correctly rejecting alert_count=0.
        """
        with pytest.raises(ValidationError) as excinfo:
            SiemAlertFinding(
                alert_id="ALERT-0",
                asset_id="ASSET-1",
                rule_name="Zero Count Rule",
                alert_count=0,
            )
        assert "greater_than_equal" in str(excinfo.value)

    def test_siem_alert_count_one_hundred_thousand_saturation(self):
        """
        Boundary: SIEM alert with alert_count = 100,000.
        Verifies velocity capping at 50, preventing numerical overflow or runaway TEF.
        """
        alert = SiemAlertFinding(
            alert_id="ALERT-100K",
            asset_id="ASSET-1",
            rule_name="DDoS Event Storm",
            alert_count=100000,
            brute_force=True,
            confidence=0.9,
        )
        norm = TelemetryNormalizer.normalize_siem(alert)
        # CF is capped at: 0.5 + 0.15 * min(alert_count, 50) = 0.5 + 0.15 * 50 = 8.0
        # PoA = 0.60 (brute force); tef = 8.0 * 0.60 * 0.9 = 4.32
        assert norm.threat_event_frequency == 4.32
        # Resistance strength remains within [0.02, 0.99]
        assert 0.02 <= norm.resistance_strength <= 0.99
        assert not math.isinf(norm.threat_event_frequency)
        assert not math.isnan(norm.threat_event_frequency)

    def test_extreme_domain_attributes(self):
        """Probes extreme boundary attributes across IAM, EDR, and CSPM."""
        # IAM: 10,000 inactive days
        iam = IamFinding(
            identity_id="IAM-EXTREME",
            asset_id="ASSET-1",
            account_name="ancient_admin",
            role="GlobalAdmin",
            is_admin=True,
            mfa_enabled=False,
            is_dormant=True,
            inactive_days=10000,
            excess_privileges=True,
        )
        norm_iam = TelemetryNormalizer.normalize_iam(iam)
        assert norm_iam.severity == SeverityLevel.CRITICAL
        assert 0.02 <= norm_iam.resistance_strength <= 0.99
        assert norm_iam.threat_event_frequency > 0.0

        # EDR: 50,000 active threats (deg = 0.40 + 0.35 + 0.10 = 0.85; rs = 0.15 * (1 - 0.85) = 0.0225)
        edr = EdrTelemetryFinding(
            agent_id="EDR-STORM",
            asset_id="ASSET-1",
            endpoint_hostname="compromised-node.corp",
            agent_status=EdrStatus.STOPPED,
            active_threats_count=50000,
            suspicious_process_injection=True,
            tamper_protection=False,
            days_since_update=0,
        )
        norm_edr = TelemetryNormalizer.normalize_edr(edr)
        assert norm_edr.severity == SeverityLevel.CRITICAL
        assert norm_edr.resistance_strength == 0.0225

        # EDR: with stale definitions (days > 14 adds 0.15; deg = min(0.95, 1.0) = 0.95; rs = max(0.02, 0.0075) = 0.02)
        edr_stale = EdrTelemetryFinding(
            agent_id="EDR-STALE",
            asset_id="ASSET-1",
            endpoint_hostname="compromised-node.corp",
            agent_status=EdrStatus.STOPPED,
            active_threats_count=50000,
            suspicious_process_injection=True,
            tamper_protection=False,
            days_since_update=30,
        )
        norm_edr_stale = TelemetryNormalizer.normalize_edr(edr_stale)
        assert norm_edr_stale.resistance_strength == 0.02

        # CSPM: 65535 ports open
        all_ports = list(range(1, 1024)) + [3389, 445, 1433, 5432, 27017]
        cspm = CspmFinding(
            resource_id="CSPM-FLOOD",
            asset_id="ASSET-1",
            cloud_provider=CloudProvider.AWS,
            service="SecurityGroup",
            public_exposure=True,
            open_ports=all_ports,
            unencrypted_data=True,
            missing_backup=True,
            compliance_drift_count=500,
        )
        norm_cspm = TelemetryNormalizer.normalize_cspm(cspm)
        assert norm_cspm.severity == SeverityLevel.CRITICAL
        # CSPM mathematical floor: rs_base = 0.85, max deg = 0.95 -> 0.85 * (1 - 0.95) = 0.0425
        assert norm_cspm.resistance_strength == 0.0425


# ===========================================================================
# 3. Ingestion Performance & Memory Footprint with 1,000+ Findings
# ===========================================================================
class TestScalePerformanceAndMemory:
    """Stress-test throughput, execution time, and memory footprint at scale."""

    def test_ingestion_and_normalization_1000_heterogeneous_findings(self):
        """
        Stress: Ingest and normalize 1,000 heterogeneous findings across 5 domains.
        Verifies:
        - Latency < 500ms
        - Peak memory overhead < 15MB
        - Zero unhandled exceptions
        - 100% mathematical invariant compliance on all 1,000 records
        """
        tracemalloc.start()
        t0 = time.perf_counter()

        raw_records = []
        for i in range(1000):
            domain_idx = i % 5
            if domain_idx == 0:  # Vulnerability
                raw_records.append({
                    "finding_id": f"VULN-{i}",
                    "asset_id": f"ASSET-{i % 65}",
                    "cve_id": f"CVE-2024-{2000 + i}",
                    "cvss_score": round((i % 101) / 10.0, 1),
                    "epss_score": round((i % 101) / 100.0, 2),
                    "cisa_kev": (i % 5 == 0),
                    "attack_vector": "NETWORK" if i % 2 == 0 else "LOCAL",
                })
            elif domain_idx == 1:  # SIEM
                raw_records.append({
                    "alert_id": f"SIEM-{i}",
                    "asset_id": f"ASSET-{i % 65}",
                    "rule_name": f"Detection Rule {i % 10}",
                    "alert_count": max(1, i % 50),
                    "brute_force": (i % 3 == 0),
                    "lateral_movement": (i % 4 == 0),
                    "exfiltration": (i % 7 == 0),
                    "confidence": 0.85,
                })
            elif domain_idx == 2:  # IAM
                raw_records.append({
                    "identity_id": f"IAM-{i}",
                    "asset_id": f"ASSET-{i % 65}",
                    "account_name": f"user_{i}@apex.corp",
                    "role": "Admin" if i % 2 == 0 else "Analyst",
                    "is_admin": (i % 2 == 0),
                    "mfa_enabled": (i % 3 != 0),
                    "is_dormant": (i % 4 == 0),
                    "inactive_days": (i % 180),
                    "excess_privileges": (i % 5 == 0),
                })
            elif domain_idx == 3:  # EDR
                raw_records.append({
                    "agent_id": f"EDR-{i}",
                    "asset_id": f"ASSET-{i % 65}",
                    "endpoint_hostname": f"host-{i % 65}.apex.corp",
                    "agent_status": "HEALTHY" if i % 2 == 0 else "DEGRADED",
                    "active_threats_count": i % 5,
                    "suspicious_process_injection": (i % 6 == 0),
                    "tamper_protection": True,
                })
            else:  # CSPM
                raw_records.append({
                    "resource_id": f"CSPM-{i}",
                    "asset_id": f"ASSET-{i % 65}",
                    "cloud_provider": "AWS" if i % 2 == 0 else "AZURE",
                    "service": "S3" if i % 3 == 0 else "SecurityGroup",
                    "public_exposure": (i % 3 == 0),
                    "open_ports": [22, 443] if i % 3 == 0 else [],
                    "unencrypted_data": (i % 4 == 0),
                    "compliance_drift_count": i % 5,
                })

        json_adapter = JsonTelemetryAdapter()
        parsed = json_adapter.parse(raw_records)
        assert len(parsed) == 1000

        normalized = TelemetryNormalizer.normalize_batch(parsed)
        t1 = time.perf_counter()
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        elapsed_ms = (t1 - t0) * 1000
        peak_mb = peak_mem / (1024 * 1024)

        assert len(normalized) == 1000
        assert elapsed_ms < 500.0, f"Normalization too slow: {elapsed_ms:.2f} ms"
        assert peak_mb < 15.0, f"Memory footprint exceeded limit: {peak_mb:.2f} MB"

        # Invariant checks across all 1,000 findings
        for f in normalized:
            assert 0.0 <= f.cvss_score <= 10.0
            assert 0.0 <= f.epss_score <= 1.0
            assert f.threat_event_frequency >= 0.0
            assert 0.02 <= f.resistance_strength <= 0.99
            assert isinstance(f.severity, SeverityLevel)
            assert isinstance(f.domain, TelemetryDomain)
            assert f.asset_id.startswith("ASSET-")

    def test_high_volume_alert_stream_throughput(self):
        """
        Stress: 5,000 SIEM alerts normalization throughput.
        Verifies throughput exceeds 5,000 alerts/second.
        """
        alerts = [
            {
                "alert_id": f"SIEM-BURST-{i}",
                "asset_id": f"ASSET-{i % 50}",
                "rule_name": f"Rule {i % 20}",
                "alert_count": max(1, i % 100),
                "confidence": 0.8,
            }
            for i in range(5000)
        ]
        t0 = time.perf_counter()
        normalized = TelemetryNormalizer.normalize_batch(alerts, TelemetryDomain.SIEM)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        throughput = len(normalized) / elapsed

        assert len(normalized) == 5000
        assert throughput > 5000, f"Throughput {throughput:.1f} alerts/sec below 5,000 threshold"


# ===========================================================================
# 4. Asset Criticality Dynamic Finding Impact Ratio (>7,000x) Stress
# ===========================================================================
class TestAssetCriticalityDynamicImpactStress:
    """Stress-test the Dynamic Finding Impact Ratio across severity spectrum."""

    def test_dynamic_impact_ratio_across_cvss_spectrum(self):
        """
        Verifies that identical technical findings produce >7,000x financial impact difference
        between Core Payment DB and Sandbox across all CVSS severity tiers (10.0, 7.5, 5.0, 2.0).
        """
        gen = ApexEnterpriseGenerator(seed=42)
        assets, findings, graph = gen.generate_enterprise_dataset()

        pay_db = next(a for a in assets if a.asset_id == "PAY-DB-01")
        sandbox = next(a for a in assets if a.asset_id == "CORP-DEV-SANDBOX-01")

        for test_cvss in [10.0, 7.5, 5.0, 2.0]:
            impact_pay = calculate_finding_impact(test_cvss, pay_db, graph)
            impact_sandbox = calculate_finding_impact(test_cvss, sandbox, graph)

            assert impact_pay > 0.0
            assert impact_sandbox > 0.0

            ratio = impact_pay / impact_sandbox
            assert ratio > 7000.0, (
                f"Impact ratio {ratio:.2f} failed to exceed 7,000x for CVSS {test_cvss} "
                f"(Pay: ${impact_pay:,.2f}, Sandbox: ${impact_sandbox:,.2f})"
            )


# ===========================================================================
# 5. Dependency Graph Resilience & Cyclic Anomaly Stress
# ===========================================================================
class TestDependencyGraphResilience:
    """Stress-tests EnterpriseDependencyGraph under cyclic, disconnected, and invalid topology."""

    def test_graph_self_loop_and_cycle_rejection(self):
        """Probes DAG validation with self-loops, 2-node cycles, and transitive cycles."""
        graph = EnterpriseDependencyGraph()

        # Self-loop: A -> A
        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("ASSET-A", "ASSET-A")

        # 2-Node Cycle: A -> B, B -> A
        graph.add_dependency("ASSET-A", "ASSET-B")
        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("ASSET-B", "ASSET-A")

        # Transitive Cycle: A -> B -> C, C -> A
        graph.add_dependency("ASSET-B", "ASSET-C")
        with pytest.raises(ValueError, match="creates a cyclic dependency"):
            graph.add_dependency("ASSET-C", "ASSET-A")

        # Verify graph remains a valid DAG after rejected additions
        assert graph.is_valid_dag()
        topo_order = graph.topological_sort()
        assert len(topo_order) == 3

    def test_graph_unregistered_and_isolated_node_percolation(self):
        """Probes failure percolation for assets not registered in graph."""
        graph = EnterpriseDependencyGraph()
        # Querying an unregistered asset ID
        result = graph.percolate_failure("GHOST-ASSET-404")
        assert result.asset_id == "GHOST-ASSET-404"
        assert result.impacted_services == []
        assert result.impacted_assets == []
        assert result.total_upstream_revenue_per_hour == 0.0
        assert result.service_reachability_ratio == 0.0

    def test_graph_massive_disconnected_components(self):
        """Probes centrality and topological sort on 500 disconnected nodes."""
        graph = EnterpriseDependencyGraph()
        for i in range(500):
            graph.graph.add_node(f"DISCONNECTED-{i}", node_type="asset")

        assert graph.is_valid_dag()
        centrality = graph.calculate_centrality()
        assert len(centrality) == 500
        # For disconnected nodes, betweenness centrality must be exactly 0.0
        for i in range(500):
            assert centrality[f"DISCONNECTED-{i}"]["betweenness_centrality"] == 0.0


# ===========================================================================
# 6. High-Volume 100,000 Alerts Scale & Memory Test
# ===========================================================================
class TestHighVolume100kAlertsScale:
    """Stress-test 100,000 SIEM alerts ingestion and normalization."""

    def test_100k_siem_alerts_full_stream(self):
        """
        Stress: Ingest and normalize 100,000 SIEM alerts.
        Measures:
        - Total processing duration
        - Peak memory consumption (must not exhaust system RAM, threshold < 300 MB)
        - Invariant integrity across 100,000 outputs
        """
        tracemalloc.start()
        t0 = time.perf_counter()

        alerts = [
            {
                "alert_id": f"ALERT-BULK-{i}",
                "asset_id": f"HOST-{i % 100}",
                "rule_name": f"Rule-Type-{i % 10}",
                "alert_count": max(1, i % 200),
                "brute_force": (i % 2 == 0),
                "lateral_movement": (i % 5 == 0),
                "confidence": 0.85,
            }
            for i in range(100000)
        ]
        t_gen = time.perf_counter()

        adapter = JsonTelemetryAdapter()
        parsed = adapter.parse(alerts)
        t_parse = time.perf_counter()

        normalized = TelemetryNormalizer.normalize_batch(parsed, TelemetryDomain.SIEM)
        t_norm = time.perf_counter()

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        elapsed_total = t_norm - t0
        peak_mb = peak_mem / (1024 * 1024)

        assert len(normalized) == 100000
        assert peak_mb < 300.0, f"Memory {peak_mb:.2f} MB exceeded 300 MB limit"
        assert elapsed_total < 25.0, f"Processing {elapsed_total:.2f}s exceeded 25s limit"

        # Spot-check invariants on first, middle, and last records
        for idx in [0, 50000, 99999]:
            rec = normalized[idx]
            assert rec.domain == TelemetryDomain.SIEM
            assert 0.02 <= rec.resistance_strength <= 0.99
            assert rec.threat_event_frequency > 0.0
            assert not math.isnan(rec.threat_event_frequency)
            assert not math.isinf(rec.threat_event_frequency)


# ===========================================================================
# 7. Payload Boundary & Large String Injections
# ===========================================================================
class TestPayloadBoundaryAttacks:
    """Stress-test payloads with huge strings, special unicode characters, and injection attempts."""

    def test_extreme_string_size_handling(self):
        """Probes Pydantic models with 1MB title string."""
        huge_title = "A" * 1_000_000

        vuln = VulnerabilityFinding(
            finding_id="VULN-HUGE-STR",
            asset_id="ASSET-PROD-01",
            cve_id="CVE-2024-99999",
            title=huge_title,
            cvss_score=8.5,
            epss_score=0.25,
        )
        norm = TelemetryNormalizer.normalize_vulnerability(vuln)
        assert len(norm.title) == 1_000_000
        assert norm.cvss_score == 8.5

    def test_special_unicode_and_control_characters(self):
        """Probes normalization with special UTF-8, zero-width spaces, and control characters."""
        hostile_rule_name = "Rule\u0000\u200b\u200e\ufeff\U0001f4a3 Alert <script>alert(1)</script>"
        alert = SiemAlertFinding(
            alert_id="ALERT-UNICODE",
            asset_id="ASSET-\u00e9\u00e8\u00e0",
            rule_name=hostile_rule_name,
            alert_count=5,
        )
        norm = TelemetryNormalizer.normalize_siem(alert)
        assert norm.title == hostile_rule_name
        assert norm.asset_id == "ASSET-\u00e9\u00e8\u00e0"

    def test_batch_failure_atomic_behavior(self):
        """
        Probes behavior of normalize_batch when a single corrupt item is embedded in a batch.
        Empirical finding: normalize_batch is strict/atomic: raising ValidationError on first invalid item.
        """
        batch = [
            {"finding_id": "V1", "asset_id": "A1", "cve_id": "CVE-1", "cvss_score": 7.0},
            {"finding_id": "CORRUPT", "cvss_score": "not_a_number"},  # invalid item
            {"finding_id": "V3", "asset_id": "A3", "cve_id": "CVE-3", "cvss_score": 8.0},
        ]
        with pytest.raises(ValidationError):
            TelemetryNormalizer.normalize_batch(batch, TelemetryDomain.VULNERABILITY)

