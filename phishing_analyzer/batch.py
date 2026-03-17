"""Parallel batch URL analysis using ThreadPoolExecutor."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from phishing_analyzer.models import AnalysisResult


def batch_analyze(
    urls: list[str],
    analyze_fn: Callable[[str], AnalysisResult],
    max_workers: int = 4,
) -> list[AnalysisResult]:
    """Analyze multiple URLs in parallel.

    Returns results in the same order as the input URLs.
    """
    results: dict[int, AnalysisResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {executor.submit(analyze_fn, url): i for i, url in enumerate(urls)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()
    return [results[i] for i in range(len(urls))]
