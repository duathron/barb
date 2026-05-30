"""JSON and CSV export for barb analysis results."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from ..models import AnalysisResult


def _default(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_json(result: AnalysisResult, indent: int = 2, defang: bool = True) -> str:
    """Serialize a single analysis result to JSON.

    When *defang* is False the ``defanged_url`` field in the output is set to
    the original URL (no defanging applied), matching ``--no-defang`` semantics.
    """
    data = result.model_dump(mode="json")
    if not defang:
        data["defanged_url"] = result.url
    return json.dumps(data, indent=indent, default=_default, ensure_ascii=False)


def to_json_list(results: list[AnalysisResult], indent: int = 2, defang: bool = True) -> str:
    """Serialize a list of analysis results to a JSON array.

    When *defang* is False the ``defanged_url`` field in each object is set to
    the original URL, matching ``--no-defang`` semantics.
    """
    data = [r.model_dump(mode="json") for r in results]
    if not defang:
        for item, result in zip(data, results):
            item["defanged_url"] = result.url
    return json.dumps(data, indent=indent, default=_default, ensure_ascii=False)


def to_csv(results: list[AnalysisResult]) -> str:
    """Flatten analysis results to CSV (one row per URL)."""
    out = io.StringIO()
    fields = [
        "url",
        "defanged_url",
        "verdict",
        "risk_score",
        "signal_count",
        "signals_summary",
        "explanation",
        "analyzed_at",
    ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for r in results:
        signals_summary = "|".join(
            f"{s.severity.value}:{s.analyzer}:{s.label}" for s in r.signals
        )
        writer.writerow(
            {
                "url": r.url,
                "defanged_url": r.defanged_url,
                "verdict": r.verdict.value,
                "risk_score": f"{r.risk_score:.1f}",
                "signal_count": len(r.signals),
                "signals_summary": signals_summary,
                "explanation": r.explanation or "",
                "analyzed_at": r.analyzed_at.isoformat(),
            }
        )
    return out.getvalue()
