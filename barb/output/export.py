"""JSON and CSV export for barb analysis results."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime
from typing import Any

from ..models import AnalysisResult, RiskVerdict


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


def to_ndjson(results: list[AnalysisResult], defang: bool = True) -> str:
    """Serialize analysis results to newline-delimited JSON (NDJSON).

    One compact JSON object per line, trailing newline.  When *defang* is
    False the ``defanged_url`` field is set to the original URL for each
    object, matching ``--no-defang`` semantics.
    """
    lines: list[str] = []
    for result in results:
        data = result.model_dump(mode="json")
        if not defang:
            data["defanged_url"] = result.url
        lines.append(json.dumps(data, separators=(",", ":"), default=_default, ensure_ascii=False))
    return "\n".join(lines) + "\n"


# STIX 2.1 verdict metadata
_STIX_VERDICT_INCLUDE = {RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING}
_STIX_CONFIDENCE = {
    RiskVerdict.SUSPICIOUS: 50,
    RiskVerdict.HIGH_RISK: 75,
    RiskVerdict.PHISHING: 95,
}


def to_stix(results: list[AnalysisResult]) -> str:
    """Serialize qualifying analysis results to a STIX 2.1 Bundle JSON string.

    Only SUSPICIOUS, HIGH_RISK, and PHISHING verdicts are emitted as Indicator
    SDOs.  SAFE and LOW_RISK are skipped — a benign URL is not a threat
    indicator.  If no results qualify the bundle is returned with an empty
    ``objects`` list.

    URLs are never defanged in STIX output — the pattern field must contain
    the raw URL so that consumers can match it programmatically.
    """
    objects: list[dict[str, Any]] = []

    for result in results:
        if result.verdict not in _STIX_VERDICT_INCLUDE:
            continue

        indicator_id = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, result.url))
        ts = result.analyzed_at.isoformat()

        # Escape single quotes in the URL per STIX pattern string rules
        escaped_url = result.url.replace("'", "''")
        pattern = f"[url:value = '{escaped_url}']"

        # Truncate very long URLs in the human-readable name
        display_url = result.url if len(result.url) <= 120 else result.url[:120] + "..."
        name = f"Phishing indicator: {result.verdict.value} ({display_url})"

        signals_summary = "; ".join(
            f"{s.severity.value}:{s.analyzer}:{s.label}" for s in result.signals
        )
        description = (
            f"Verdict: {result.verdict.value}, Risk score: {result.risk_score:.1f}. "
            f"Signals: {signals_summary if signals_summary else 'none'}"
        )

        indicator_types = ["malicious-activity"]
        if result.verdict == RiskVerdict.PHISHING:
            indicator_types.append("phishing")

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": ts,
                "modified": ts,
                "name": name,
                "description": description,
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": ts,
                "indicator_types": indicator_types,
                "confidence": _STIX_CONFIDENCE[result.verdict],
            }
        )

    bundle: dict[str, Any] = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)


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
