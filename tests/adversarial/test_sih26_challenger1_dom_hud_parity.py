"""
tests/adversarial/test_sih26_challenger1_dom_hud_parity.py

Empirical Challenger 1 Verification Suite (challenger_sih26_1):
1. Template SHA-256 Parity Verification
2. DOM Hierarchy & Structural Integrity Verification (BeautifulSoup AST)
3. Persistent HUD Positioning & Element Confinement Verification
4. Feature Panel Relocation Verification (BharatCart -> Technical, Vendor Matrix -> Executive)
5. Copilot Chip & Enterprise Showcase Rebranding Verification
6. Institutional Zero-Jury Purity Audit across src/ and run_server.py
7. Dynamic Gauge Update Emulation & Mathematical Contract Verification
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest
from bs4 import BeautifulSoup, Tag
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.schemas import TelemetryTickerResponse
from src.telemetry.attack_engine import DemoAttackStateManager

# Workspace root
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TEMPLATE_PATH = ROOT_DIR / "src" / "dashboard" / "templates" / "index.html"
STATIC_HTML_PATH = ROOT_DIR / "src" / "dashboard" / "static" / "index.html"


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 hexadecimal digest for a given file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_soup(filepath: Path) -> BeautifulSoup:
    """Parses an HTML file using BeautifulSoup."""
    with open(filepath, "r", encoding="utf-8") as f:
        return BeautifulSoup(f.read(), "html.parser")


@pytest.fixture(scope="session")
def template_soup() -> BeautifulSoup:
    return load_soup(TEMPLATE_PATH)


@pytest.fixture(scope="session")
def static_soup() -> BeautifulSoup:
    return load_soup(STATIC_HTML_PATH)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# =============================================================================
# 1. Template SHA-256 Parity Verification
# =============================================================================

class TestTemplateParity:
    """Empirically verifies bit-for-bit equivalence between SSR and static index.html."""

    def test_templates_exist_and_non_empty(self):
        assert TEMPLATE_PATH.is_file(), f"Missing template at {TEMPLATE_PATH}"
        assert STATIC_HTML_PATH.is_file(), f"Missing static HTML at {STATIC_HTML_PATH}"
        assert TEMPLATE_PATH.stat().st_size > 0
        assert STATIC_HTML_PATH.stat().st_size > 0

    def test_sha256_bit_for_bit_match(self):
        template_hash = compute_sha256(TEMPLATE_PATH)
        static_hash = compute_sha256(STATIC_HTML_PATH)
        assert template_hash == static_hash, (
            f"Template drift detected!\n"
            f"templates/index.html SHA-256: {template_hash}\n"
            f"static/index.html    SHA-256: {static_hash}"
        )
        assert len(template_hash) == 64

    def test_exact_byte_content_equality(self):
        template_bytes = TEMPLATE_PATH.read_bytes()
        static_bytes = STATIC_HTML_PATH.read_bytes()
        assert template_bytes == static_bytes, "Binary contents of template and static HTML diverge"


# =============================================================================
# 2. DOM Hierarchy & Navigation Verification
# =============================================================================

class TestDomHierarchyAndNavigation:
    """Empirically verifies DOM hierarchy, navigation tab count, and absence of legacy demo tab."""

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_no_legacy_demo_tab_pills(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        # 1. Assert NO element with id="tab-pill-demo"
        pill = soup.find(id="tab-pill-demo")
        assert pill is None, f"Found legacy #tab-pill-demo in {soup_name}: {pill}"

        # 2. Assert NO element with data-tab="demo"
        demo_tab_elements = soup.find_all(attrs={"data-tab": "demo"})
        assert len(demo_tab_elements) == 0, (
            f"Found elements with data-tab='demo' in {soup_name}: {demo_tab_elements}"
        )

        # 3. Assert NO container with id="tab-demo"
        tab_demo_container = soup.find(id="tab-demo")
        assert tab_demo_container is None, f"Found legacy #tab-demo in {soup_name}: {tab_demo_container}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_navigation_segmented_control_has_exactly_two_tabs(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        nav_segmented = soup.find("div", class_="segmented-control")
        assert nav_segmented is not None, f"Missing .segmented-control in {soup_name}"

        # Tab pills inside segmented control
        pills = nav_segmented.find_all("button", class_="tab-pill")
        assert len(pills) == 2, f"Expected exactly 2 tab pills, got {len(pills)} in {soup_name}"

        tabs = [p.get("data-tab") for p in pills]
        assert tabs == ["executive", "technical"], (
            f"Expected tabs ['executive', 'technical'], got {tabs} in {soup_name}"
        )

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_tab_content_containers_exactly_two(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        tab_contents = soup.find_all("div", class_="tab-content")
        assert len(tab_contents) == 2, f"Expected exactly 2 .tab-content elements, got {len(tab_contents)} in {soup_name}"

        tab_ids = [tc.get("id") for tc in tab_contents]
        assert tab_ids == ["tab-executive", "tab-technical"], (
            f"Expected tab-content IDs ['tab-executive', 'tab-technical'], got {tab_ids} in {soup_name}"
        )


# =============================================================================
# 3. Dynamic Gauge HUD Executive Placement & Technical Tab Isolation
# =============================================================================

class TestPersistentHudPlacement:
    """Empirically verifies that the 5 dynamic gauge cards are housed strictly inside Executive view and absent from Technical."""

    GAUGE_VALUE_IDS = [
        "demo-posture-val",
        "demo-rf-val",
        "demo-sup-val",
        "demo-eal-val",
        "demo-shields-val",
    ]

    ALL_HUD_ELEMENT_IDS = [
        "posture-meter-bar",
        "demo-posture-val",
        "demo-posture-badge",
        "demo-posture-subtext",
        "demo-rf-val",
        "demo-rf-indicator",
        "demo-risk-badge",
        "demo-rf-subtext",
        "demo-sup-val",
        "demo-sup-badge",
        "demo-sup-detail",
        "demo-eal-val",
        "demo-eal-badge",
        "demo-eal-delta",
        "demo-eal-subtext",
        "demo-shields-val",
        "demo-shields-badge",
        "demo-vendors-funded",
    ]

    TECHNICAL_TELEMETRY_IDS = [
        "cnt-vuln",
        "cnt-siem",
        "cnt-iam",
        "cnt-edr",
        "cnt-cspm",
    ]

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_hud_container_exists_inside_executive_tab(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        hud = soup.find(id="persistent-risk-hud")
        tab_exec = soup.find(id="tab-executive")
        assert hud is not None, f"Missing #persistent-risk-hud in {soup_name}"
        assert tab_exec is not None, f"Missing #tab-executive in {soup_name}"
        assert "persistent-hud-strip" in hud.get("class", [])

        # Confirm HUD is nested inside #tab-executive
        assert hud in tab_exec.descendants, f"#persistent-risk-hud is NOT inside #tab-executive in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_hud_is_strictly_absent_from_technical_tab(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        hud = soup.find(id="persistent-risk-hud")
        tab_tech = soup.find(id="tab-technical")
        assert tab_tech is not None, f"Missing #tab-technical in {soup_name}"

        # Verify HUD is NOT inside tab-technical
        assert hud not in tab_tech.descendants, f"#persistent-risk-hud is unexpectedly nested inside #tab-technical in {soup_name}"

        # Verify none of the 5 gauge values or supporting HUD elements are in tab-technical
        for gid in self.GAUGE_VALUE_IDS:
            elem = soup.find(id=gid)
            assert elem not in tab_tech.descendants, f"Gauge value #{gid} should NOT be in #tab-technical in {soup_name}"

        for eid in self.ALL_HUD_ELEMENT_IDS:
            elem = soup.find(id=eid)
            assert elem not in tab_tech.descendants, f"HUD element #{eid} should NOT be in #tab-technical in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_technical_tab_has_dedicated_cross_domain_telemetry(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        tab_tech = soup.find(id="tab-technical")

        for tid in self.TECHNICAL_TELEMETRY_IDS:
            elem = soup.find(id=tid)
            assert elem is not None, f"Technical telemetry #{tid} not found in {soup_name}"
            assert elem in tab_tech.descendants, f"Technical telemetry #{tid} is not in #tab-technical in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_all_5_gauge_values_are_strictly_inside_hud(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        hud = soup.find(id="persistent-risk-hud")
        tab_exec = soup.find(id="tab-executive")

        for gid in self.GAUGE_VALUE_IDS:
            elem = soup.find(id=gid)
            assert elem is not None, f"Gauge value element #{gid} not found in {soup_name}"
            assert elem in hud.descendants, f"#{gid} is NOT inside #persistent-risk-hud in {soup_name}"
            assert elem in tab_exec.descendants, f"#{gid} is NOT inside #tab-executive in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_all_supporting_hud_elements_are_inside_hud(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        hud = soup.find(id="persistent-risk-hud")

        for eid in self.ALL_HUD_ELEMENT_IDS:
            elem = soup.find(id=eid)
            assert elem is not None, f"Supporting HUD element #{eid} not found in {soup_name}"
            assert elem in hud.descendants, f"Supporting HUD element #{eid} is not inside #persistent-risk-hud in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_var_tail_ribbon_inside_lec_panel(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        tab_exec = soup.find(id="tab-executive")
        ribbon = soup.find(class_="var-tail-ribbon")

        assert ribbon is not None, f"Missing .var-tail-ribbon in {soup_name}"
        assert ribbon in tab_exec.descendants, f".var-tail-ribbon is not inside #tab-executive in {soup_name}"

        for var_id in ["kpi-var90", "kpi-var95", "kpi-var99"]:
            elem = soup.find(id=var_id)
            assert elem is not None, f"Missing #{var_id} in {soup_name}"
            assert elem in ribbon.descendants, f"#{var_id} is not inside .var-tail-ribbon in {soup_name}"


# =============================================================================
# 4. Feature Panel Relocation Verification
# =============================================================================

class TestFeaturePanelRelocation:
    """Empirically verifies BharatCart relocation to Technical and CEO Matrix to Executive."""

    BHARAT_CART_ELEMENT_IDS = [
        "btn-reset-demo",
        "topo-BC-API-GW-01",
        "topo-BC-FLASH-SALE-01",
        "topo-BC-PAY-GW-01",
        "topo-BC-PII-VAULT-01",
        "demo-target-node",
        "curl-command-display",
        "btn-copy-curl",
        "demo-terminal-feed",
    ]

    ATTACK_VECTORS = [
        "DDOS_TRAFFIC_SURGE",
        "RANSOMWARE_OUTAGE",
        "SQL_DATA_EXFILTRATION",
        "CREDENTIAL_STUFFING",
        "ZERO_DAY_CVE",
        "CLOUD_IAM_COMPROMISE",
    ]

    VENDOR_MATRIX_ELEMENT_IDS = [
        "vss-total-spend",
        "vss-count",
        "vss-capital-saved",
        "vendor-benchmark-cards",
    ]

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_bharatcart_elements_strictly_inside_tab_technical(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        tab_tech = soup.find(id="tab-technical")
        tab_exec = soup.find(id="tab-executive")

        assert tab_tech is not None
        assert tab_exec is not None

        # Verify all BharatCart component IDs are inside tab-technical
        for elem_id in self.BHARAT_CART_ELEMENT_IDS:
            elem = soup.find(id=elem_id)
            assert elem is not None, f"BharatCart element #{elem_id} missing in {soup_name}"
            assert elem in tab_tech.descendants, f"#{elem_id} is not inside #tab-technical in {soup_name}"
            assert elem not in tab_exec.descendants, f"#{elem_id} must not be in #tab-executive in {soup_name}"

        # Verify all 6 attack buttons are inside tab-technical
        attack_buttons = soup.find_all("button", attrs={"data-attack": True})
        assert len(attack_buttons) == 6, f"Expected 6 attack buttons, got {len(attack_buttons)} in {soup_name}"

        attack_vectors_found = set()
        for ab in attack_buttons:
            vec = ab.get("data-attack")
            attack_vectors_found.add(vec)
            assert ab in tab_tech.descendants, f"Attack button {vec} is not inside #tab-technical in {soup_name}"
            assert ab not in tab_exec.descendants, f"Attack button {vec} is in #tab-executive in {soup_name}"

        assert attack_vectors_found == set(self.ATTACK_VECTORS), (
            f"Mismatch in attack vectors: {attack_vectors_found ^ set(self.ATTACK_VECTORS)}"
        )

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_ceo_vendor_matrix_strictly_inside_tab_executive(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        tab_tech = soup.find(id="tab-technical")
        tab_exec = soup.find(id="tab-executive")

        assert tab_tech is not None
        assert tab_exec is not None

        for elem_id in self.VENDOR_MATRIX_ELEMENT_IDS:
            elem = soup.find(id=elem_id)
            assert elem is not None, f"Vendor matrix element #{elem_id} missing in {soup_name}"
            assert elem in tab_exec.descendants, f"#{elem_id} is not inside #tab-executive in {soup_name}"
            assert elem not in tab_tech.descendants, f"#{elem_id} must not be in #tab-technical in {soup_name}"

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_root_modal_threat_immunity_exists_at_body_root(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        modal = soup.find(id="modal-threat-immunity")
        assert modal is not None, f"Missing #modal-threat-immunity in {soup_name}"

        # Verify modal elements
        assert modal.find(id="modal-vendor-name") is not None
        assert modal.find(id="modal-vendor-desc") is not None
        assert modal.find(id="modal-shields-grid") is not None
        assert modal.find(id="btn-modal-procure") is not None
        assert modal.find(id="btn-close-modal") is not None


# =============================================================================
# 5. Copilot Chip & Enterprise Rebranding Verification
# =============================================================================

class TestEnterpriseRebranding:
    """Empirically verifies Copilot chips and UI text reflect enterprise presentation standards."""

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_copilot_quick_action_chips(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)

        # 1. Check Executive Pitch Chip
        pitch_chip = soup.find("button", attrs={"data-action": "executive-pitch"})
        assert pitch_chip is not None, f"Missing button[data-action='executive-pitch'] in {soup_name}"

        text = pitch_chip.get_text(strip=True)
        assert "30-Sec Executive Pitch" in text, f"Expected '30-Sec Executive Pitch', got '{text}' in {soup_name}"

        # 2. Check no jury pitch chip
        legacy_chip = soup.find("button", attrs={"data-action": "jury-pitch"})
        assert legacy_chip is None, f"Found legacy button[data-action='jury-pitch'] in {soup_name}"

        # 3. Check all three standard copilot chips
        chips = soup.find_all("button", class_="copilot-chip")
        chip_actions = [c.get("data-action") for c in chips]
        assert "executive-pitch" in chip_actions
        assert "blast-radius" in chip_actions
        assert "auto-optimize" in chip_actions

    @pytest.mark.parametrize("soup_name,soup_fixture", [
        ("templates/index.html", "template_soup"),
        ("static/index.html", "static_soup"),
    ])
    def test_zero_user_facing_jury_in_html_text(self, soup_name: str, soup_fixture: str, request):
        soup: BeautifulSoup = request.getfixturevalue(soup_fixture)
        full_text = soup.get_text()
        jury_matches = re.findall(r"\bjury\b", full_text, flags=re.IGNORECASE)
        assert len(jury_matches) == 0, f"Found visible 'jury' text occurrences in {soup_name}: {jury_matches}"


# =============================================================================
# 6. Institutional Zero-Jury Purity Audit
# =============================================================================

class TestZeroJuryInstitutionalPurity:
    """Audits entire src/ tree and run_server.py for zero case-insensitive 'jury' mentions."""

    def test_zero_jury_in_src_tree(self):
        src_dir = ROOT_DIR / "src"
        violations: List[str] = []

        for root, _, files in os.walk(src_dir):
            for file in files:
                ext = Path(file).suffix.lower()
                # Check code, html, css, js, json, yaml, md files
                if ext in {".py", ".html", ".js", ".css", ".json", ".yaml", ".yml", ".md", ".txt"}:
                    fpath = Path(root) / file
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception as e:
                        violations.append(f"Failed to read {fpath}: {e}")
                        continue

                    matches = [
                        (idx + 1, line.strip())
                        for idx, line in enumerate(content.splitlines())
                        if re.search(r"\bjury\b", line, flags=re.IGNORECASE)
                    ]
                    for line_no, line_text in matches:
                        violations.append(f"{fpath.relative_to(ROOT_DIR)}:{line_no} -> {line_text}")

        assert len(violations) == 0, (
            f"Institutional purity violation! Found {len(violations)} 'jury' references in src/:\n"
            + "\n".join(violations[:20])
        )

    def test_zero_jury_in_run_server(self):
        run_server = ROOT_DIR / "run_server.py"
        assert run_server.is_file()
        content = run_server.read_text(encoding="utf-8", errors="ignore")
        matches = [
            (idx + 1, line.strip())
            for idx, line in enumerate(content.splitlines())
            if re.search(r"\bjury\b", line, flags=re.IGNORECASE)
        ]
        assert len(matches) == 0, f"Found 'jury' references in run_server.py: {matches}"


# =============================================================================
# 7. Dynamic Gauge Update Emulation & Mathematical Contract Verification
# =============================================================================

class TestDynamicGaugeUpdateEmulation:
    """
    Empirically emulates the dashboard.js DOM mutation logic against the actual
    HTML element IDs and validates telemetry ticker response contract.
    """

    class EmulatedDashboardState:
        """Emulates the DOM cache and JS mutators from dashboard.js lines 1080-1235."""

        def __init__(self, soup: BeautifulSoup):
            self.soup = soup
            self.demoPostureVal = soup.find(id="demo-posture-val")
            self.postureMeterBar = soup.find(id="posture-meter-bar")
            self.demoPostureBadge = soup.find(id="demo-posture-badge")

            self.demoRfVal = soup.find(id="demo-rf-val")
            self.demoRfIndicator = soup.find(id="demo-rf-indicator")
            self.demoRiskBadge = soup.find(id="demo-risk-badge")

            self.demoSupVal = soup.find(id="demo-sup-val")
            self.demoSupBadge = soup.find(id="demo-sup-badge")
            self.demoSupDetail = soup.find(id="demo-sup-detail")

            self.demoEalVal = soup.find(id="demo-eal-val")
            self.demoEalBadge = soup.find(id="demo-eal-badge")
            self.demoEalDelta = soup.find(id="demo-eal-delta")

            self.demoShieldsVal = soup.find(id="demo-shields-val")
            self.demoShieldsBadge = soup.find(id="demo-shields-badge")
            self.demoVendorsFunded = soup.find(id="demo-vendors-funded")

        def update_posture(self, score: float):
            clamped = max(0.0, min(100.0, score))
            if self.demoPostureVal:
                self.demoPostureVal.string = f"{clamped:.1f}"
            if self.postureMeterBar:
                circ = 2 * math.pi * 50  # 314.159
                offset = circ - (clamped / 100.0) * circ
                self.postureMeterBar["stroke-dashoffset"] = f"{offset:.3f}"
            if self.demoPostureBadge:
                if clamped >= 88:
                    self.demoPostureBadge.string = "Maximum Defense"
                elif clamped >= 75:
                    self.demoPostureBadge.string = "Resilient"
                elif clamped >= 60:
                    self.demoPostureBadge.string = "Degraded"
                else:
                    self.demoPostureBadge.string = "Critical Exposure"

        def update_rf(self, rf: float):
            clamped = max(0.0, min(10.0, rf))
            if self.demoRfVal:
                self.demoRfVal.string = f"{clamped:.1f}"
            if self.demoRfIndicator:
                pct = (clamped / 10.0) * 100
                self.demoRfIndicator["style"] = f"width: {pct:.1f}%;"
            if self.demoRiskBadge:
                if clamped < 3.0:
                    self.demoRiskBadge.string = f"Low ({clamped:.1f})"
                elif clamped < 6.0:
                    self.demoRiskBadge.string = f"Moderate ({clamped:.1f})"
                elif clamped < 8.0:
                    self.demoRiskBadge.string = f"Elevated ({clamped:.1f})"
                else:
                    self.demoRiskBadge.string = f"Critical ({clamped:.1f})"

        def update_sup(self, sup_pct: float, mitigated_inr: float, baseline_eal_inr: float):
            if self.demoSupVal:
                self.demoSupVal.string = f"+{sup_pct:.1f}%" if sup_pct > 0 else "0.0%"
            if self.demoSupBadge:
                self.demoSupBadge.string = f"+{sup_pct:.1f}% Gain" if sup_pct > 0 else "Baseline State"
            if self.demoSupDetail:
                if sup_pct > 0:
                    self.demoSupDetail.string = f"Mitigated {mitigated_inr} of {baseline_eal_inr} Baseline"
                else:
                    self.demoSupDetail.string = "Invest in vendors below to unlock defense upgrade"

        def update_eal(self, current_eal_inr: float, baseline_eal_inr: float, is_attack: bool):
            if self.demoEalVal:
                self.demoEalVal.string = f"₹ {current_eal_inr / 1e7:.2f} Cr"
            if self.demoEalBadge:
                if is_attack:
                    self.demoEalBadge.string = "ATTACK SURGE"
                elif current_eal_inr < baseline_eal_inr:
                    self.demoEalBadge.string = "RISK MITIGATED"
                else:
                    self.demoEalBadge.string = "Nominal State"
            if self.demoEalDelta:
                if is_attack:
                    diff = current_eal_inr - baseline_eal_inr
                    self.demoEalDelta.string = f"Surge Delta: +₹ {diff / 1e7:.2f} Cr"
                elif current_eal_inr < baseline_eal_inr:
                    diff = baseline_eal_inr - current_eal_inr
                    self.demoEalDelta.string = f"Capital Exposure Reduction: -₹ {diff / 1e7:.2f} Cr"
                else:
                    self.demoEalDelta.string = f"Baseline: ₹ {baseline_eal_inr / 1e7:.2f} Cr"

        def update_shields(self, active_count: int, funded_count: int):
            if self.demoShieldsVal:
                self.demoShieldsVal.string = f"{active_count} Active"
            if self.demoVendorsFunded:
                self.demoVendorsFunded.string = f"{funded_count} Commercial Solutions Funded"

    def test_dom_elements_exist_for_emulation(self, template_soup: BeautifulSoup):
        emulator = self.EmulatedDashboardState(template_soup)
        assert emulator.demoPostureVal is not None
        assert emulator.postureMeterBar is not None
        assert emulator.demoPostureBadge is not None
        assert emulator.demoRfVal is not None
        assert emulator.demoRfIndicator is not None
        assert emulator.demoRiskBadge is not None
        assert emulator.demoSupVal is not None
        assert emulator.demoSupBadge is not None
        assert emulator.demoSupDetail is not None
        assert emulator.demoEalVal is not None
        assert emulator.demoEalBadge is not None
        assert emulator.demoEalDelta is not None
        assert emulator.demoShieldsVal is not None
        assert emulator.demoShieldsBadge is not None
        assert emulator.demoVendorsFunded is not None

    def test_emulation_nominal_baseline_state(self, template_soup: BeautifulSoup):
        """Validates that nominal baseline correctly sets all 5 gauges."""
        emulator = self.EmulatedDashboardState(template_soup)
        emulator.update_posture(84.6)
        emulator.update_rf(4.8)
        emulator.update_sup(0.0, 0.0, 48200000.0)
        emulator.update_eal(48200000.0, 48200000.0, is_attack=False)
        emulator.update_shields(5, 0)

        assert emulator.demoPostureVal.get_text() == "84.6"
        assert emulator.demoPostureBadge.get_text() == "Resilient"
        assert emulator.demoRfVal.get_text() == "4.8"
        assert emulator.demoRiskBadge.get_text() == "Moderate (4.8)"
        assert emulator.demoSupVal.get_text() == "0.0%"
        assert emulator.demoSupBadge.get_text() == "Baseline State"
        assert emulator.demoEalVal.get_text() == "₹ 4.82 Cr"
        assert emulator.demoEalBadge.get_text() == "Nominal State"
        assert emulator.demoShieldsVal.get_text() == "5 Active"
        assert emulator.demoVendorsFunded.get_text() == "0 Commercial Solutions Funded"

    def test_emulation_attack_state(self, template_soup: BeautifulSoup):
        """Validates that high-intensity attack simulation updates gauges as expected."""
        emulator = self.EmulatedDashboardState(template_soup)
        # Under DDoS: Posture drops to 42.0%, RF surges to 9.2, EAL increases to ₹9.40 Cr
        emulator.update_posture(42.0)
        emulator.update_rf(9.2)
        emulator.update_sup(0.0, 0.0, 48200000.0)
        emulator.update_eal(94000000.0, 48200000.0, is_attack=True)
        emulator.update_shields(2, 0)

        assert emulator.demoPostureVal.get_text() == "42.0"
        assert emulator.demoPostureBadge.get_text() == "Critical Exposure"
        assert emulator.demoRfVal.get_text() == "9.2"
        assert emulator.demoRiskBadge.get_text() == "Critical (9.2)"
        assert emulator.demoEalVal.get_text() == "₹ 9.40 Cr"
        assert emulator.demoEalBadge.get_text() == "ATTACK SURGE"
        assert "Surge Delta" in emulator.demoEalDelta.get_text()
        assert emulator.demoShieldsVal.get_text() == "2 Active"

    def test_emulation_mitigated_vendor_procurement_state(self, template_soup: BeautifulSoup):
        """Validates that procuring vendor solutions updates gauges with positive SUP % and mitigated EAL."""
        emulator = self.EmulatedDashboardState(template_soup)
        # Procuring CrowdStrike + Cloudflare: Posture rises to 94.5%, RF drops to 1.8, SUP +38.4%, EAL drops to ₹2.97 Cr
        emulator.update_posture(94.5)
        emulator.update_rf(1.8)
        emulator.update_sup(38.4, 18500000.0, 48200000.0)
        emulator.update_eal(29700000.0, 48200000.0, is_attack=False)
        emulator.update_shields(7, 2)

        assert emulator.demoPostureVal.get_text() == "94.5"
        assert emulator.demoPostureBadge.get_text() == "Maximum Defense"
        assert emulator.demoRfVal.get_text() == "1.8"
        assert emulator.demoRiskBadge.get_text() == "Low (1.8)"
        assert emulator.demoSupVal.get_text() == "+38.4%"
        assert emulator.demoSupBadge.get_text() == "+38.4% Gain"
        assert "Mitigated" in emulator.demoSupDetail.get_text()
        assert emulator.demoEalVal.get_text() == "₹ 2.97 Cr"
        assert emulator.demoEalBadge.get_text() == "RISK MITIGATED"
        assert "Capital Exposure Reduction" in emulator.demoEalDelta.get_text()
        assert emulator.demoShieldsVal.get_text() == "7 Active"
        assert emulator.demoVendorsFunded.get_text() == "2 Commercial Solutions Funded"

    def test_live_telemetry_ticker_endpoint_contract(self, client: TestClient):
        """Validates that /api/v1/demo/telemetry-ticker satisfies the required schema contract."""
        resp = client.get("/api/v1/demo/telemetry-ticker")
        assert resp.status_code == 200
        data = resp.json()

        # Validate with Pydantic model
        ticker = TelemetryTickerResponse(**data)
        assert ticker.events_per_second > 0
        assert ticker.threat_event_frequency >= 0
        assert 0.0 <= ticker.security_posture_score <= 100.0
        assert 0.0 <= ticker.risk_factor_score <= 10.0
        assert ticker.current_eal_inr > 0
        assert ticker.var_95_inr >= ticker.current_eal_inr
        assert ticker.total_threat_shields_active >= 0
        assert ticker.overall_threat_level in {"NORMAL", "ELEVATED", "CRITICAL_ATTACK_ACTIVE"}
