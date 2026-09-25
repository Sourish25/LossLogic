"""
tests/unit/test_xai.py - Unit test suite for Explainable AI (XAI) & Model Transparency layer.
"""

import asyncio
from src.ai.xai import (
    XAIEngine,
    FeatureAttribution,
    DecisionTraceStep,
    CounterfactualExplanation,
    XAIExplanationResult,
    AISummaryResult,
    get_xai_engine,
)


def test_xai_deterministic_attributions():
    engine = XAIEngine()
    attributions = engine._compute_deterministic_attributions("Explain why Core DB is highest risk", currency="INR")
    assert len(attributions) == 4
    total_weight = sum(a.weight_pct for a in attributions)
    assert 99.0 <= total_weight <= 101.0
    names = [a.feature_name for a in attributions]
    assert any("Vulnerability" in n for n in names)
    assert any("Asset Criticality" in n for n in names)


def test_xai_budget_attributions():
    engine = XAIEngine()
    attributions = engine._compute_deterministic_attributions("Why did MILP select this budget allocation?", currency="INR")
    assert len(attributions) == 4
    names = [a.feature_name for a in attributions]
    assert any("Marginal Risk Reduction" in n for n in names)


def test_xai_decision_trace():
    engine = XAIEngine()
    trace = engine._compute_deterministic_decision_trace("Why is this asset flagged?", currency="INR")
    assert len(trace) >= 4
    assert trace[0].step_number == 1
    assert "Telemetry" in trace[0].stage
    assert any("Monte Carlo" in step.observation or "Monte Carlo" in step.formula_or_model for step in trace)


def test_xai_counterfactual():
    engine = XAIEngine()
    cf = engine._compute_deterministic_counterfactual(currency="INR")
    assert cf.expected_roi_pct > 0
    assert "₹" in cf.baseline_eal
    assert "₹" in cf.counterfactual_eal


def test_xai_explain_end_to_end():
    engine = XAIEngine()
    res = asyncio.run(
        engine.explain(
            query="Explain why Core Banking DB has the highest risk",
            currency="INR",
        )
    )
    assert isinstance(res, XAIExplanationResult)
    assert len(res.feature_attributions) == 4
    assert len(res.decision_trace) >= 4
    assert res.transparency_score > 90.0
    assert "Core Banking" in res.plain_text_explanation or "BC-PII-VAULT-01" in res.plain_text_explanation


def test_xai_summarize_end_to_end():
    engine = XAIEngine()
    summary = asyncio.run(
        engine.summarize(
            target_audience="board",
            currency="INR",
        )
    )
    assert isinstance(summary, AISummaryResult)
    assert len(summary.key_findings) >= 3
    assert len(summary.prioritized_actions) >= 2
    assert "current_eal_formatted" in summary.monetary_breakdown


def test_xai_api_endpoints():
    from fastapi.testclient import TestClient
    from src.api.app import app

    client = TestClient(app)

    # 1. Test XAI explain endpoint
    resp = client.post(
        "/api/v1/ai/xai-explain",
        json={"query": "Explain why Core Banking DB is our highest risk", "currency": "INR"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "headline" in data
    assert "feature_attributions" in data
    assert len(data["feature_attributions"]) == 4
    assert "decision_trace" in data
    assert "counterfactual" in data
    assert data["transparency_score"] > 90

    # 2. Test AI summarize endpoint
    resp_sum = client.post(
        "/api/v1/ai/summarize",
        json={"target_audience": "board", "scope": "enterprise", "currency": "INR"}
    )
    assert resp_sum.status_code == 200
    sum_data = resp_sum.json()
    assert "summary_30s" in sum_data
    assert len(sum_data["key_findings"]) >= 3
    assert "monetary_breakdown" in sum_data

