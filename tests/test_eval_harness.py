"""Smoke tests for the offline eval harness (eval/run_eval.py) and corpus
builder (eval/fetch_corpus.py).

100% offline — no real network calls.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from barb.models import RiskVerdict
from eval.run_eval import EvalMetrics, gate_failures, load_corpus, run_eval

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
        f"FPR {metrics.false_positive_rate:.3f} exceeds 0.5 — too many well-known benign domains are being flagged."
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
        "tp",
        "fp",
        "tn",
        "fn",
        "errors",
        "precision",
        "recall",
        "f1",
        "accuracy",
        "false_positive_rate",
        "tier_breakdown",
    }
    assert required.issubset(d.keys())


# ---------------------------------------------------------------------------
# gate_failures unit tests (no analyzer, no fixture run)
# ---------------------------------------------------------------------------


def _metrics(tp: int, fp: int, fn: int, tn: int = 0) -> EvalMetrics:
    """Build a minimal EvalMetrics with known confusion-matrix values."""
    return EvalMetrics(tp=tp, fp=fp, tn=tn, fn=fn)


def test_gate_failures_all_pass():
    """Metrics above both floors → empty failures list."""
    # precision = 4/(4+0) = 1.0, recall = 4/(4+1) = 0.8
    m = _metrics(tp=4, fp=0, fn=1)
    assert gate_failures(m, min_precision=1.0, min_recall=0.70) == []


def test_gate_failures_precision_floor():
    """Precision below floor → failure message mentioning 'precision'."""
    # precision = 3/(3+2) = 0.6, recall = 3/(3+0) = 1.0
    m = _metrics(tp=3, fp=2, fn=0)
    failures = gate_failures(m, min_precision=0.9, min_recall=None)
    assert len(failures) == 1
    assert "precision" in failures[0].lower()


def test_gate_failures_recall_floor():
    """Recall below floor → failure message mentioning 'recall'."""
    # precision = 2/(2+0) = 1.0, recall = 2/(2+3) = 0.4
    m = _metrics(tp=2, fp=0, fn=3)
    failures = gate_failures(m, min_precision=None, min_recall=0.70)
    assert len(failures) == 1
    assert "recall" in failures[0].lower()


def test_gate_failures_none_floors():
    """No floors set → always returns empty list regardless of metrics."""
    # precision = 0.0 (tp=0), recall = 0.0 (tp=0)
    m = _metrics(tp=0, fp=5, fn=5)
    assert gate_failures(m, min_precision=None, min_recall=None) == []


# ---------------------------------------------------------------------------
# run_eval: --osint pass-through
# ---------------------------------------------------------------------------


def test_run_eval_passes_osint_true(monkeypatch, tmp_path):
    """run_eval(osint=True) must forward osint=True to every _analyze_single call."""
    from eval import run_eval as run_eval_module

    # Write a tiny one-row corpus
    corpus = tmp_path / "mini.csv"
    corpus.write_text("url,label\nhttps://example.com,benign\n")

    calls: list[dict] = []

    def fake_analyze(url, config, explain=False, osint=False, use_cache=True):
        calls.append({"url": url, "osint": osint})
        # Return a real-looking result by running the actual analyzer
        from barb.main import _analyze_single as real_analyze

        return real_analyze(url, config, explain=explain, osint=False, use_cache=False)

    monkeypatch.setattr(run_eval_module, "_analyze_single", fake_analyze)
    run_eval(corpus_path=corpus, osint=True)

    assert calls, "fake_analyze was never called"
    assert all(c["osint"] is True for c in calls), f"Expected all calls to have osint=True, got: {calls}"


def test_run_eval_osint_default_false(monkeypatch, tmp_path):
    """run_eval() without osint argument must forward osint=False (offline default)."""
    from eval import run_eval as run_eval_module

    corpus = tmp_path / "mini.csv"
    corpus.write_text("url,label\nhttps://example.com,benign\n")

    calls: list[dict] = []

    def fake_analyze(url, config, explain=False, osint=False, use_cache=True):
        calls.append({"url": url, "osint": osint})
        from barb.main import _analyze_single as real_analyze

        return real_analyze(url, config, explain=explain, osint=False, use_cache=False)

    monkeypatch.setattr(run_eval_module, "_analyze_single", fake_analyze)
    run_eval(corpus_path=corpus)  # no osint= arg

    assert calls, "fake_analyze was never called"
    assert all(c["osint"] is False for c in calls), f"Expected all calls to have osint=False, got: {calls}"


# ---------------------------------------------------------------------------
# fetch_corpus: write_corpus
# ---------------------------------------------------------------------------


def test_write_corpus_creates_csv(tmp_path):
    """write_corpus writes header + correct label rows."""
    from eval.fetch_corpus import write_corpus

    phishing = ["https://evil.tk/login", "https://paypa1.verify.ml/secure"]
    benign = ["https://google.com/", "https://github.com/"]

    out = tmp_path / "test_corpus.csv"
    result = write_corpus(phishing, benign, out)

    assert result == out.resolve()
    assert out.exists()

    rows = load_corpus(out)
    urls = [u for u, _ in rows]
    row_labels = [lbl for _, lbl in rows]

    # All phishing URLs present with correct label
    for url in phishing:
        assert url in urls
        assert row_labels[urls.index(url)] == "phishing"

    # All benign URLs present with correct label
    for url in benign:
        assert url in urls
        assert row_labels[urls.index(url)] == "benign"


def test_write_corpus_deduplication(tmp_path):
    """Duplicate URLs are written only once (first occurrence wins)."""
    from eval.fetch_corpus import write_corpus

    phishing = ["https://evil.tk/", "https://evil.tk/"]  # duplicate
    benign = ["https://good.com/", "https://good.com/"]  # duplicate

    out = tmp_path / "dedup.csv"
    write_corpus(phishing, benign, out)

    rows = load_corpus(out)
    urls = [u for u, _ in rows]
    assert len(urls) == len(set(urls)), "duplicate URLs should be removed"
    assert len(urls) == 2  # one phishing + one benign


def test_write_corpus_cross_label_dedup(tmp_path):
    """A URL appearing in both lists is only written once (phishing wins — first seen)."""
    from eval.fetch_corpus import write_corpus

    shared = "https://shared.example.com/"
    phishing = [shared]
    benign = [shared]  # same URL in both

    out = tmp_path / "cross_dedup.csv"
    write_corpus(phishing, benign, out)

    rows = load_corpus(out)
    urls = [u for u, _ in rows]
    assert urls.count(shared) == 1, "shared URL should appear exactly once"


def test_write_corpus_creates_parent_dirs(tmp_path):
    """Parent directories are created if they do not exist."""
    from eval.fetch_corpus import write_corpus

    out = tmp_path / "a" / "b" / "c" / "corpus.csv"
    write_corpus(["https://evil.example/"], ["https://safe.example/"], out)
    assert out.exists()


def test_write_corpus_reloadable_by_load_corpus(tmp_path):
    """CSV written by write_corpus is valid for load_corpus."""
    from eval.fetch_corpus import write_corpus

    phishing = [f"https://phish{i}.tk/" for i in range(3)]
    benign = [f"https://safe{i}.com/" for i in range(3)]

    out = tmp_path / "reload.csv"
    write_corpus(phishing, benign, out)
    rows = load_corpus(out)

    assert len(rows) == 6
    assert {label for _, label in rows} == {"phishing", "benign"}


# ---------------------------------------------------------------------------
# fetch_corpus: fetch_phishing
# ---------------------------------------------------------------------------


def test_fetch_phishing_rejects_non_https():
    """Non-https source URL must raise RuntimeError without any network call."""
    from eval.fetch_corpus import fetch_phishing

    with pytest.raises(RuntimeError, match="HTTPS required"):
        fetch_phishing("http://evil.com/feed.txt")


def test_fetch_phishing_rejects_ftp():
    """FTP scheme must also be rejected."""
    from eval.fetch_corpus import fetch_phishing

    with pytest.raises(RuntimeError, match="HTTPS required"):
        fetch_phishing("ftp://feeds.example.com/phish.txt")


def test_fetch_phishing_parses_feed(tmp_path):
    """Mocked urlopen returns a plain-text feed; fetch_phishing parses it correctly."""
    from eval.fetch_corpus import fetch_phishing

    feed_content = (
        "https://evil1.tk/login\n# this is a comment\n\nhttps://evil2.ml/verify\n  https://evil3.cf/secure  \n"
    )

    mock_resp = MagicMock()
    mock_resp.read.side_effect = [feed_content.encode(), b""]
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("eval.fetch_corpus.urlopen", return_value=mock_resp):
        urls = fetch_phishing("https://openphish.example.com/feed.txt")

    assert urls == [
        "https://evil1.tk/login",
        "https://evil2.ml/verify",
        "https://evil3.cf/secure",
    ]


def test_fetch_phishing_size_cap(tmp_path):
    """Responses exceeding 50 MB are rejected."""
    from eval.fetch_corpus import _MAX_BYTES, fetch_phishing

    # Build a mock that streams just over the cap
    chunk_size = 65536
    oversized_chunk = b"x" * chunk_size
    call_count = (_MAX_BYTES // chunk_size) + 2  # enough to exceed cap

    mock_resp = MagicMock()
    mock_resp.read.side_effect = [oversized_chunk] * call_count
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("eval.fetch_corpus.urlopen", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="size cap"):
            fetch_phishing("https://feeds.example.com/feed.txt")


# ---------------------------------------------------------------------------
# fetch_corpus: build_benign
# ---------------------------------------------------------------------------


def _make_tranco_zip(domains: list[str]) -> bytes:
    """Build a minimal Tranco-style ZIP (rank,domain CSV) in memory."""
    csv_lines = ["rank,domain"] + [f"{i + 1},{d}" for i, d in enumerate(domains)]
    csv_bytes = "\n".join(csv_lines).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", csv_bytes)
    return buf.getvalue()


def test_build_benign_returns_https_urls():
    """build_benign returns https://<domain>/ URLs for the mocked Tranco domains."""
    from eval.fetch_corpus import build_benign

    domains = ["google.com", "github.com", "wikipedia.org"]
    fake_zip = _make_tranco_zip(domains)

    with (
        patch("eval.fetch_corpus.fetch_tranco", return_value=fake_zip),
        patch("eval.fetch_corpus.parse_tranco", return_value=domains) as mock_parse,
    ):
        urls = build_benign(top_n=3, tranco_url="https://tranco.example.com/top.zip")

    mock_parse.assert_called_once_with(fake_zip, top_n=3)
    assert urls == [f"https://{d}/" for d in domains]


def test_build_benign_passes_top_n():
    """build_benign forwards top_n to parse_tranco."""
    from eval.fetch_corpus import build_benign

    with (
        patch("eval.fetch_corpus.fetch_tranco", return_value=b"fake"),
        patch("eval.fetch_corpus.parse_tranco", return_value=["a.com", "b.com"]) as mock_parse,
    ):
        build_benign(top_n=99, tranco_url="https://tranco.example.com/top.zip")

    mock_parse.assert_called_once_with(b"fake", top_n=99)


def test_build_benign_uses_default_tranco_url():
    """build_benign uses _DEFAULT_TRANCO_URL when tranco_url is None."""
    from barb.data_update import _DEFAULT_TRANCO_URL
    from eval.fetch_corpus import build_benign

    captured: list[str] = []

    def fake_fetch(url, timeout=30.0):
        captured.append(url)
        return b"fake"

    with (
        patch("eval.fetch_corpus.fetch_tranco", side_effect=fake_fetch),
        patch("eval.fetch_corpus.parse_tranco", return_value=["x.com"]),
    ):
        build_benign(top_n=1)

    assert captured == [_DEFAULT_TRANCO_URL]
