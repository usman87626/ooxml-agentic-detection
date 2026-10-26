"""
test_timing.py — unit tests for PipelineTimings.
"""

import time
import pytest
from extractor.timing import PipelineTimings, StageTimingRecord, measure_ms


class TestPipelineTimings:
    def test_context_manager_records_stage(self):
        t = PipelineTimings()
        with t.stage("zip_enumeration"):
            pass
        records = t.to_list()
        assert len(records) == 1
        assert records[0]["name"] == "zip_enumeration"
        assert records[0]["time_ms"] >= 0.0

    def test_multiple_stages(self):
        t = PipelineTimings()
        for name in ["zip_enumeration", "xml_parsing", "macro_extraction"]:
            with t.stage(name):
                pass
        records = t.to_list()
        assert len(records) == 3
        names = [r["name"] for r in records]
        assert names == ["zip_enumeration", "xml_parsing", "macro_extraction"]

    def test_stage_measures_real_time(self):
        t = PipelineTimings()
        with t.stage("sleep_test"):
            time.sleep(0.01)  # 10 ms
        assert t.get("sleep_test") >= 9.0  # at least 9 ms

    def test_total_ms_after_finish(self):
        t = PipelineTimings()
        with t.stage("noop"):
            pass
        t.finish()
        assert t.total_ms >= 0.0

    def test_total_ms_before_finish(self):
        t = PipelineTimings()
        with t.stage("noop"):
            pass
        # Should still work without calling finish()
        assert t.total_ms >= 0.0

    def test_stage_exception_still_records(self):
        t = PipelineTimings()
        try:
            with t.stage("erroring"):
                raise ValueError("test error")
        except ValueError:
            pass
        assert len(t.to_list()) == 1
        assert t.to_list()[0]["name"] == "erroring"

    def test_get_missing_stage(self):
        t = PipelineTimings()
        assert t.get("nonexistent") == 0.0

    def test_to_dict_schema(self):
        t = PipelineTimings()
        with t.stage("test"):
            pass
        t.finish()
        d = t.to_dict()
        assert "total_ms" in d
        assert "stages" in d
        assert isinstance(d["stages"], list)


class TestMeasureMs:
    def test_returns_result_and_time(self):
        result, ms = measure_ms(lambda: 42)
        assert result == 42
        assert ms >= 0.0

    def test_propagates_exception(self):
        with pytest.raises(ValueError):
            measure_ms(lambda: (_ for _ in ()).throw(ValueError("oops")))


class TestStageTimingRecord:
    def test_to_dict(self):
        r = StageTimingRecord(name="test_stage", time_ms=12.345)
        d = r.to_dict()
        assert d["name"] == "test_stage"
        assert d["time_ms"] == 12.345
