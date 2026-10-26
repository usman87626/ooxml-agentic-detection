"""
test_macro_extractor.py — unit tests for VBA macro extraction error handling.
"""

import pytest
from extractor.macro_vba_extractor import (
    _find_keywords,
    _is_vba_container,
    AUTO_EXEC_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
)


class TestKeywordFinding:
    def test_autoopen_found(self):
        code = "Sub AutoOpen()\n  Shell \"cmd\"\nEnd Sub"
        found = _find_keywords(code, AUTO_EXEC_KEYWORDS)
        assert "AutoOpen" in found

    def test_multiple_keywords(self):
        code = "Sub Workbook_Open()\n  CreateObject(\"WScript.Shell\").Run(\"cmd\")\nEnd Sub"
        auto = _find_keywords(code, AUTO_EXEC_KEYWORDS)
        susp = _find_keywords(code, SUSPICIOUS_KEYWORDS)
        assert "Workbook_Open" in auto
        assert "CreateObject" in susp

    def test_no_false_positives_on_clean_code(self):
        code = "Sub HelloWorld()\n  MsgBox \"Hello\"\nEnd Sub"
        auto = _find_keywords(code, AUTO_EXEC_KEYWORDS)
        susp = _find_keywords(code, SUSPICIOUS_KEYWORDS)
        assert auto == []
        assert susp == []

    def test_case_insensitive_match(self):
        code = "sub autoopen()\nend sub"
        found = _find_keywords(code, AUTO_EXEC_KEYWORDS)
        assert "AutoOpen" in found


class TestVbaContainerDetection:
    def test_vbaproject_bin_detected(self):
        assert _is_vba_container("xl/vbaProject.bin", b"\xD0\xCF" + b"\x00" * 100)

    def test_any_path_vbaproject(self):
        assert _is_vba_container("word/vbaProject.bin", b"")

    def test_ole_magic_detected(self):
        ole_magic = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 100
        assert _is_vba_container("some/random/file.bin", ole_magic)

    def test_non_ole_not_detected(self):
        assert not _is_vba_container("word/document.xml", b"<?xml version")
        assert not _is_vba_container("image.png", b"\x89PNG")


class TestExtractMacrosGraceful:
    """extract_macros must not raise even when oletools is unavailable or file is non-OLE."""

    def test_empty_entries(self):
        from extractor.macro_vba_extractor import extract_macros
        result = extract_macros({})
        assert result.containers_found == []

    def test_non_ole_entries_ignored(self):
        from extractor.macro_vba_extractor import extract_macros
        entries = {
            "word/document.xml": b"<?xml version='1.0'?><doc/>",
            "image.png": b"\x89PNG",
        }
        result = extract_macros(entries)
        assert result.containers_found == []

    def test_ole_binary_handled_gracefully(self):
        """Even a fake OLE blob should not crash the extractor."""
        from extractor.macro_vba_extractor import extract_macros
        # fabricated OLE magic + garbage
        fake_ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 512
        entries = {"vbaProject.bin": fake_ole}
        result = extract_macros(entries)
        assert "vbaProject.bin" in result.containers_found
        # Error should be recorded, not raised
        assert len(result.results) == 1
        assert result.results[0].error != "" or result.results[0].extraction_log != ""
