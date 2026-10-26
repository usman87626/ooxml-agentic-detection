"""
test_xlm_extractor.py — unit tests for XLM / Excel 4.0 macro detection.
"""

import pytest
from extractor.xlm_extractor import extract_xlm, _detect_suspicious, SUSPICIOUS_XLM_FUNCTIONS

# Sample xl/macrosheets/sheet1.xml content
_MACROSHEET_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1"><f>EXEC("cmd /c calc.exe")</f><v>0</v></c>
    </row>
    <row r="2">
      <c r="A2"><f>REGISTER("kernel32","WinExec","JCJ","WinExec",1,1,0)</f><v>0</v></c>
    </row>
    <row r="3">
      <c r="A3"><f>HALT()</f><v>0</v></c>
    </row>
    <row r="4">
      <c r="B1"><f>SUM(1,2)</f><v>3</v></c>
    </row>
  </sheetData>
</worksheet>
"""

_CLEAN_WORKSHEET_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1"><v>Hello</v></c>
    </row>
  </sheetData>
</worksheet>
"""


class TestXlmExtractor:
    def test_macrosheet_path_detected(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        assert "xl/macrosheets/sheet1.xml" in findings.macro_sheet_paths

    def test_exec_function_detected(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        assert len(findings.sheets) == 1
        sheet = findings.sheets[0]
        assert "EXEC" in sheet.all_suspicious_functions

    def test_register_function_detected(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        sheet = findings.sheets[0]
        assert "REGISTER" in sheet.all_suspicious_functions

    def test_halt_function_detected(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        sheet = findings.sheets[0]
        assert "HALT" in sheet.all_suspicious_functions

    def test_clean_formula_not_flagged(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        sheet = findings.sheets[0]
        # SUM should NOT be in suspicious functions
        assert "SUM" not in sheet.all_suspicious_functions

    def test_clean_worksheet_ignored(self):
        entries = {"xl/worksheets/sheet1.xml": _CLEAN_WORKSHEET_XML}
        findings = extract_xlm(entries)
        assert findings.macro_sheet_paths == []
        assert findings.sheets == []

    def test_empty_entries(self):
        findings = extract_xlm({})
        assert findings.macro_sheet_paths == []
        assert findings.sheets == []

    def test_detect_suspicious_helper(self):
        assert "EXEC" in _detect_suspicious("EXEC(\"evil\")")
        assert "REGISTER" in _detect_suspicious("REGISTER(1,2,3)")
        assert [] == _detect_suspicious("SUM(A1:A10)")

    def test_all_suspicious_functions_populated(self):
        entries = {"xl/macrosheets/sheet1.xml": _MACROSHEET_XML}
        findings = extract_xlm(entries)
        sheet = findings.sheets[0]
        assert len(sheet.all_suspicious_functions) >= 3
