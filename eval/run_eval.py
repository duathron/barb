"""Offline evaluation harness for barb.

Measures detection quality (precision / recall / F1) against a labeled CSV corpus.
OSINT enrichers are disabled by default; pass ``--osint`` to enable them (opt-in,
live network, slower).

Usage:
    python -m eval.run_eval
    python -m eval.run_eval --corpus path/to/corpus.csv
    python -m eval.run_eval --json
    python -m eval.run_eval --alert-tier HIGH_RISK --json
    python -m eval.run_eval --corpus eval/corpus/real.csv --osint
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Verdict ordering (mirrors barb/scoring.py _VERDICT_ORDER)
# ---------------------------------------------------------------------------
from barb.config import load_config
from barb.main import _analyze_single
from barb.models import RiskVerdict

_VERDICT_ORDER: list[RiskVerdict] = [
    RiskVerdict.SAFE,
    RiskVerdict.LOW_RISK,
    RiskVerdict.SUSPICIOUS,
    RiskVerdict.HIGH_RISK,
    RiskVerdict.PHISHING,
]

_DEFAULT_CORPUS = Path(__file__).parent / "fixtures" / "sample_corpus.csv"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class EvalMetrics:
    """Confusion-matrix metrics for a binary classification run."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0
    # Per-tier breakdown: tier_name -> {"benign": int, "phishing": int}
    tier_breakdown: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return round(self.tp / denom, 4) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return round(self.tp / denom, 4) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        denom = p + r
        return round(2 * p * r / denom, 4) if denom else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return round((self.tp + self.tn) / total, 4) if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return round(self.fp / denom, 4) if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "errors": self.errors,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "false_positive_rate": self.false_positive_rate,
            "tier_breakdown": self.tier_breakdown,
        }


# ---------------------------------------------------------------------------
# Core logic (importable for tests)
# ---------------------------------------------------------------------------


def load_corpus(corpus_path: Path) -> list[tuple[str, str]]:
    """Load (url, label) pairs from a CSV file.

    Skips blank lines and lines beginning with '#'.
    Label is normalised to lowercase.  Raises ValueError on unknown labels.
    """
    rows: list[tuple[str, str]] = []
    with open(corpus_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for line_num, row in enumerate(reader, start=2):  # +2: 1-indexed + header
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not url or url.startswith("#"):
                continue
            if label not in ("phishing", "benign"):
                raise ValueError(
                    f"Unknown label {label!r} at line {line_num}. "
                    "Expected 'phishing' or 'benign'."
                )
            rows.append((url, label))
    return rows


def _verdict_gte(verdict: RiskVerdict, threshold: RiskVerdict) -> bool:
    """Return True when verdict is at or above the threshold tier."""
    return _VERDICT_ORDER.index(verdict) >= _VERDICT_ORDER.index(threshold)


def run_eval(
    corpus_path: Optional[Path] = None,
    alert_tier: RiskVerdict = RiskVerdict.SUSPICIOUS,
    osint: bool = False,
) -> EvalMetrics:
    """Load the corpus, run barb, and return EvalMetrics.

    Args:
        corpus_path: Path to a labeled CSV.  Defaults to the bundled fixture.
        alert_tier:  Verdict tier at-or-above which a URL counts as a
                     positive (alert) prediction.  Default: SUSPICIOUS.
        osint:       Enable OSINT enrichers (DNS/RDAP/crt.sh/ASN).  Default
                     False — offline, safe for CI.  Pass True only with a real
                     corpus where live lookups are acceptable.

    Returns:
        Populated EvalMetrics dataclass.
    """
    if corpus_path is None:
        corpus_path = _DEFAULT_CORPUS

    config = load_config()
    rows = load_corpus(corpus_path)

    # Initialise per-tier breakdown counters
    metrics = EvalMetrics(
        tier_breakdown={
            v.value: {"benign": 0, "phishing": 0} for v in _VERDICT_ORDER
        }
    )

    for url, label in rows:
        try:
            result = _analyze_single(url, config, osint=osint)
        except ValueError:
            metrics.errors += 1
            continue

        verdict = result.verdict
        predicted_positive = _verdict_gte(verdict, alert_tier)
        ground_truth_positive = label == "phishing"

        # Update per-tier breakdown
        metrics.tier_breakdown[verdict.value][label] += 1

        # Update confusion matrix
        if predicted_positive and ground_truth_positive:
            metrics.tp += 1
        elif predicted_positive and not ground_truth_positive:
            metrics.fp += 1
        elif not predicted_positive and ground_truth_positive:
            metrics.fn += 1
        else:
            metrics.tn += 1

    return metrics


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_rich(metrics: EvalMetrics, alert_tier: RiskVerdict) -> None:
    """Render metrics as Rich tables to stdout."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    # ---- Confusion matrix + summary metrics ----
    summary = Table(title=f"barb eval — alert tier: {alert_tier.value}", show_header=True)
    summary.add_column("Metric", style="bold cyan", no_wrap=True)
    summary.add_column("Value", justify="right")

    total = metrics.tp + metrics.fp + metrics.tn + metrics.fn
    summary.add_row("URLs evaluated", str(total))
    summary.add_row("Errors (skipped)", str(metrics.errors))
    summary.add_row("", "")
    summary.add_row("True Positives  (TP)", str(metrics.tp))
    summary.add_row("False Positives (FP)", str(metrics.fp))
    summary.add_row("True Negatives  (TN)", str(metrics.tn))
    summary.add_row("False Negatives (FN)", str(metrics.fn))
    summary.add_row("", "")
    summary.add_row("Precision", f"{metrics.precision:.4f}")
    summary.add_row("Recall", f"{metrics.recall:.4f}")
    summary.add_row("F1 Score", f"{metrics.f1:.4f}")
    summary.add_row("Accuracy", f"{metrics.accuracy:.4f}")
    summary.add_row("False-Positive Rate", f"{metrics.false_positive_rate:.4f}")

    console.print(summary)
    console.print()

    # ---- Per-tier breakdown ----
    breakdown = Table(title="Per-verdict-tier breakdown", show_header=True)
    breakdown.add_column("Verdict Tier", style="bold")
    breakdown.add_column("Benign URLs", justify="right")
    breakdown.add_column("Phishing URLs", justify="right")
    breakdown.add_column("Total", justify="right")

    for verdict in _VERDICT_ORDER:
        tier_name = verdict.value
        b = metrics.tier_breakdown[tier_name]["benign"]
        p = metrics.tier_breakdown[tier_name]["phishing"]
        marker = " *" if _verdict_gte(verdict, alert_tier) else ""
        breakdown.add_row(f"{tier_name}{marker}", str(b), str(p), str(b + p))

    console.print(breakdown)
    console.print(f"[dim]* tiers counted as positive predictions (alert tier: {alert_tier.value})[/dim]")


def _print_json(metrics: EvalMetrics, alert_tier: RiskVerdict) -> None:
    """Print metrics as JSON to stdout."""
    output = {"alert_tier": alert_tier.value}
    output.update(metrics.to_dict())
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def gate_failures(
    metrics: EvalMetrics,
    min_precision: Optional[float],
    min_recall: Optional[float],
) -> list[str]:
    """Return a list of human-readable failure strings for unmet metric floors.

    An empty list means all gates passed (or no floors were set).

    Args:
        metrics:       Populated EvalMetrics instance.
        min_precision: Required minimum precision (None = no gate).
        min_recall:    Required minimum recall (None = no gate).

    Returns:
        List of failure strings; empty when all floors are satisfied.
    """
    failures: list[str] = []
    if min_precision is not None and metrics.precision < min_precision:
        failures.append(
            f"precision gate FAILED: actual={metrics.precision:.4f} < required={min_precision:.4f}"
        )
    if min_recall is not None and metrics.recall < min_recall:
        failures.append(
            f"recall gate FAILED: actual={metrics.recall:.4f} < required={min_recall:.4f}"
        )
    return failures


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval.run_eval",
        description="Offline evaluation harness for barb — measures precision/recall/F1.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to labeled corpus CSV (default: bundled fixture).",
    )
    parser.add_argument(
        "--alert-tier",
        dest="alert_tier",
        choices=[v.value for v in _VERDICT_ORDER],
        default=RiskVerdict.SUSPICIOUS.value,
        help=(
            "Verdict tier at/above which a URL counts as a positive prediction "
            "(default: SUSPICIOUS)."
        ),
    )
    parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Emit metrics as JSON to stdout instead of a Rich table.",
    )
    parser.add_argument(
        "--min-precision",
        dest="min_precision",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Minimum required precision (0.0–1.0). Exits 1 if below this floor.",
    )
    parser.add_argument(
        "--min-recall",
        dest="min_recall",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Minimum required recall (0.0–1.0). Exits 1 if below this floor.",
    )
    parser.add_argument(
        "--osint",
        dest="osint",
        action="store_true",
        default=False,
        help=(
            "Enable OSINT enrichers (DNS/RDAP/crt.sh/ASN) during evaluation. "
            "Opt-in only — requires live network access, slower. "
            "Default: off (100%% offline, safe for CI)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point — also importable for programmatic use."""
    args = _parse_args(argv)
    alert_tier = RiskVerdict(args.alert_tier)

    metrics = run_eval(
        corpus_path=args.corpus,
        alert_tier=alert_tier,
        osint=args.osint,
    )

    if args.output_json:
        _print_json(metrics, alert_tier)
    else:
        _print_rich(metrics, alert_tier)

    # Threshold-gate: check user-supplied precision/recall floors.
    failures = gate_failures(metrics, args.min_precision, args.min_recall)
    if failures:
        for msg in failures:
            print(f"GATE: {msg}", file=sys.stderr)
        sys.exit(1)

    # Exit with non-zero when evaluation produced zero recall (nothing detected)
    # but only if there were actual phishing samples present.
    phishing_total = metrics.tp + metrics.fn
    if phishing_total > 0 and metrics.recall == 0.0:
        sys.exit(1)


if __name__ == "__main__":
    main()
