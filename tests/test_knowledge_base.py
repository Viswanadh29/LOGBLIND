"""Tests for LogBlind knowledge base loader."""

import re
from pathlib import Path

import pytest

from logblind.knowledge_base.loader import KnowledgeBaseError, KnowledgeBaseLoader


class TestKnowledgeBaseLoader:
    def test_load_builtin_kb(self):
        kb = KnowledgeBaseLoader().load()
        assert len(kb.techniques) >= 8
        ids = kb.get_technique_ids()
        # P0 techniques
        assert "T1021.001" in ids
        assert "T1021.002" in ids
        assert "T1021.006" in ids
        assert "T1047" in ids
        # P1 techniques
        assert "T1021.003" in ids
        assert "T1053.005" in ids
        assert "T1059.001" in ids
        assert "T1570" in ids

    def test_all_techniques_have_events(self):
        kb = KnowledgeBaseLoader().load()
        for t in kb.techniques:
            assert len(t.event_requirements) > 0, f"{t.technique_id} has no event requirements"

    def test_all_event_ids_positive(self):
        kb = KnowledgeBaseLoader().load()
        for t in kb.techniques:
            for req in t.event_requirements:
                assert req.event_id > 0, f"Invalid event ID in {t.technique_id}"

    def test_invalid_directory(self):
        with pytest.raises(KnowledgeBaseError):
            KnowledgeBaseLoader(kb_dir=Path("/nonexistent")).load()

    def test_technique_id_format(self):
        kb = KnowledgeBaseLoader().load()
        for t in kb.techniques:
            assert re.match(r"^T\d{4}(\.\d{3})?$", t.technique_id), f"Bad ID: {t.technique_id}"
