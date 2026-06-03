"""File-extension-in-path analyzer — detects malware-delivery indicators in URL path."""

from __future__ import annotations

import os

from barb.models import ParsedURL, Signal, SignalSeverity

# Executable / script extensions — strong delivery indicators.
_EXEC_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".scr", ".bat", ".cmd", ".msi", ".hta", ".ps1", ".vbs", ".jar", ".apk", ".dll", ".com", ".pif", ".gadget"}
)

# Document / media extensions commonly used in the masquerade trick (left of the final ext).
_DOCUMENT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".rtf",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
    }
)

# Archive extensions — low-severity (common in legit downloads too).
_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".tar"})


def _path_extensions(path: str) -> tuple[str, str]:
    """Return (penultimate_ext, final_ext) from the last path segment.

    Both are lowercased.  If the filename has only one extension the penultimate
    is an empty string.  If there is no extension both are empty strings.

    Examples:
        invoice.pdf.exe  -> (".pdf", ".exe")
        setup.exe        -> ("",     ".exe")
        README           -> ("",     "")
    """
    # Take only the filename portion (last segment).
    filename = path.rstrip("/").rsplit("/", 1)[-1]
    # Strip any query / fragment that might have leaked in (safety guard).
    filename = filename.split("?")[0].split("#")[0]

    # First splitext gives (stem, final_ext).
    stem, final_ext = os.path.splitext(filename)
    final_ext = final_ext.lower()

    # Second splitext gives (stem2, penultimate_ext).
    _, penultimate_ext = os.path.splitext(stem)
    penultimate_ext = penultimate_ext.lower()

    return penultimate_ext, final_ext


class FileExtAnalyzer:
    """Detect suspicious file extensions in the URL path (malware-delivery indicator)."""

    @property
    def name(self) -> str:
        return "file_ext"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        path = parsed_url.path or ""
        if not path or path == "/":
            return []

        penultimate_ext, final_ext = _path_extensions(path)

        if not final_ext:
            return []

        # --- Double-extension masquerade (HIGH) ---
        # e.g. invoice.pdf.exe — the left ext looks like a document/media,
        # the right ext is an executable/script.  Low FP: this pattern is
        # nearly never legitimate.
        if final_ext in _EXEC_EXTENSIONS and penultimate_ext in _DOCUMENT_EXTENSIONS:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.HIGH,
                    label="Double extension masquerade",
                    detail=(
                        f"Path ends with '{penultimate_ext}{final_ext}' — "
                        "document/media extension followed by executable/script extension "
                        "(classic masquerade trick)"
                    ),
                )
            ]

        # --- Single executable/script extension (LOW) ---
        # Common in legit software downloads too; cluster contributor.
        if final_ext in _EXEC_EXTENSIONS:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="Executable file extension in path",
                    detail=f"Path contains executable/script extension '{final_ext}'",
                )
            ]

        # --- Archive extension (INFO) ---
        # Very common in legit downloads; record but near-zero weight contribution.
        if final_ext in _ARCHIVE_EXTENSIONS:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.INFO,
                    label="Archive file extension in path",
                    detail=f"Path contains archive extension '{final_ext}'",
                )
            ]

        return []
