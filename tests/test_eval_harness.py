"""Smoke tests for the offline eval harness (eval/run_eval.py).

100% offline — no network calls, no OSINT.
"""

from __future__ import annotations

from pathlib import Path

from barb.models import RiskVerdict
from eval.run_eval import EvalMetrics, load_corpus, run_eval

_FIXTURE = Path(__file__).parent.parent / "eval" / "fixtures" / "sample_corpus.csv"


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def test_load_corpus_returns_rows():
    rows = load_corpus(_FIXTURE)
    assert len(rows) > 0, "fixture corpus should have at least one row"


def test_load_corpus_labels():
    rows = load_corpus(_FIXTURE)
    labels = {label for _, label in rows}
    assert labels == {"phishing", "benign"}, "fixture should contain both label classes"


def test_load_corpus_skips_comments_and_blanks():
    rows = load_corpus(_FIXTURE)
    for url, _ in rows:
        assert not url.startswith("#"), "comment lines must be skipped"
        assert url.strip() != "", "blank lines must be skipped"


# ---------------------------------------------------------------------------
# run_eval core
# ---------------------------------------------------------------------------


def test_run_eval_returns_metrics():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert isinstance(metrics, EvalMetrics)


def test_run_eval_metrics_populated():
    metrics = run_eval(corpus_path=_FIXTURE)
    total = metrics.tp + metrics.fp + metrics.tn + metrics.fn
    assert total > 0, "at least one URL should be evaluated"


def test_run_eval_precision_in_range():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert 0.0 <= metrics.precision <= 1.0


def test_run_eval_recall_in_range():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert 0.0 <= metrics.recall <= 1.0


def test_run_eval_f1_in_range():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert 0.0 <= metrics.f1 <= 1.0


def test_run_eval_accuracy_in_range():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert 0.0 <= metrics.accuracy <= 1.0


def test_run_eval_fpr_in_range():
    metrics = run_eval(corpus_path=_FIXTURE)
    assert 0.0 <= metrics.false_positive_rate <= 1.0


# ---------------------------------------------------------------------------
# False-positive sanity check (benign well-known domains not all flagged)
# ---------------------------------------------------------------------------


def test_false_positive_rate_below_threshold():
    """Well-known benign domains should not all be flagged.

    Bound is loose (< 0.5) to avoid brittleness if heuristics evolve.
    """
    metrics = run_eval(corpus_path=_FIXTURE)
    assert metrics.false_positive_rate < 0.5, (
        f"FPR {metrics.false_positive_rate:.3f} exceeds 0.5 — "
        "too many well-known benign domains are being flagged."
    )


# ---------------------------------------------------------------------------
# Per-tier breakdown
# ---------------------------------------------------------------------------


def test_tier_breakdown_keys():
    metrics = run_eval(corpus_path=_FIXTURE)
    expected_keys = {v.value for v in RiskVerdict}
    assert set(metrics.tier_breakdown.keys()) == expected_keys


def test_tier_breakdown_counts_non_negative():
    metrics = run_eval(corpus_path=_FIXTURE)
    for tier, counts in metrics.tier_breakdown.items():
        assert counts["benign"] >= 0, f"negative benign count for tier {tier}"
        assert counts["phishing"] >= 0, f"negative phishing count for tier {tier}"


# ---------------------------------------------------------------------------
# Alert-tier variation
# ---------------------------------------------------------------------------


def test_alert_tier_high_risk_increases_precision():
    """Raising the alert tier should not lower precision below the SUSPICIOUS run."""
    m_suspicious = run_eval(corpus_path=_FIXTURE, alert_tier=RiskVerdict.SUSPICIOUS)
    m_high_risk = run_eval(corpus_path=_FIXTURE, alert_tier=RiskVerdict.HIGH_RISK)
    # At a higher tier we may miss some phishing (lower recall is allowed),
    # but precision should be >= the lower-tier run (or at least non-zero if
    # there were any positives detected).
    if m_high_risk.tp + m_high_risk.fp > 0:
        assert m_high_risk.precision >= m_suspicious.precision - 0.05, (
            "Precision should not significantly drop when alert tier is raised."
        )


# ---------------------------------------------------------------------------
# to_dict completeness
# ---------------------------------------------------------------------------


def test_metrics_to_dict_has_all_keys():
    metrics = run_eval(corpus_path=_FIXTURE)
    d = metrics.to_dict()
    required = {
        "tp", "fp", "tn", "fn", "errors",
        "precision", "recall", "f1", "accuracy",
        "false_positive_rate", "tier_breakdown",
    }
    assert required.issubset(d.keys())
