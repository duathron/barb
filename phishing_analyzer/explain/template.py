"""Template-based explanation — no LLM required."""

from __future__ import annotations

from phishing_analyzer.models import AnalysisResult, RiskVerdict


class TemplateExplainer:
    """Generate structured explanations from signal data without an LLM."""

    def explain(self, result: AnalysisResult) -> str:
        lines: list[str] = []

        # Verdict summary
        verdict_text = {
            RiskVerdict.SAFE: "This URL appears safe. No significant phishing indicators were detected.",
            RiskVerdict.LOW_RISK: "This URL shows minor indicators that warrant awareness but low concern.",
            RiskVerdict.SUSPICIOUS: "This URL exhibits suspicious characteristics consistent with phishing attempts.",
            RiskVerdict.HIGH_RISK: "This URL shows strong phishing indicators. Exercise extreme caution.",
            RiskVerdict.PHISHING: "This URL is highly likely a phishing attempt. Do not interact with it.",
        }
        lines.append(verdict_text.get(result.verdict, "Analysis complete."))

        # Signal breakdown
        if result.signals:
            lines.append("")
            lines.append("Detected indicators:")
            for signal in sorted(result.signals, key=lambda s: s.severity.points, reverse=True):
                lines.append(f"  [{signal.severity.value}] {signal.label}: {signal.detail}")

        # Recommendation
        lines.append("")
        if result.verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING):
            lines.append("Recommendation: Block this URL and investigate the source.")
        elif result.verdict == RiskVerdict.SUSPICIOUS:
            lines.append("Recommendation: Investigate further before allowing access.")
        else:
            lines.append("Recommendation: No immediate action required.")

        return "\n".join(lines)
