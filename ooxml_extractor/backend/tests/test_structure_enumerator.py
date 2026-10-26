"""
test_structure_enumerator.py — unit tests for OoxmlRole assignment.
"""

import pytest
from extractor.structure_enumerator import assign_role, enumerate_structure, OoxmlRole


class TestRoleAssignment:
    def test_content_types(self):
        assert assign_role("[Content_Types].xml") == OoxmlRole.content_types

    def test_rels_file(self):
        assert assign_role("_rels/.rels") == OoxmlRole.relationships
        assert assign_role("word/_rels/document.xml.rels") == OoxmlRole.relationships

    def test_vba_macro_container(self):
        assert assign_role("xl/vbaProject.bin") == OoxmlRole.macro_container
        assert assign_role("word/vbaProject.bin") == OoxmlRole.macro_container

    def test_docprops_metadata(self):
        assert assign_role("docProps/core.xml") == OoxmlRole.metadata
        assert assign_role("docProps/app.xml") == OoxmlRole.metadata

    def test_customxml(self):
        assert assign_role("customXml/item1.xml") == OoxmlRole.custom_xml

    def test_theme(self):
        assert assign_role("word/theme/theme1.xml") == OoxmlRole.theme
        assert assign_role("ppt/theme/theme2.xml") == OoxmlRole.theme

    def test_word_styles(self):
        assert assign_role("word/styles.xml") == OoxmlRole.stylesheet

    def test_word_settings(self):
        assert assign_role("word/settings.xml") == OoxmlRole.settings

    def test_xl_shared_strings(self):
        assert assign_role("xl/sharedStrings.xml") == OoxmlRole.shared_strings

    def test_xl_worksheet(self):
        assert assign_role("xl/worksheets/sheet1.xml") == OoxmlRole.worksheet

    def test_xl_macrosheet(self):
        assert assign_role("xl/macrosheets/sheet1.xml") == OoxmlRole.macrosheet

    def test_ppt_slide(self):
        assert assign_role("ppt/slides/slide1.xml") == OoxmlRole.slide

    def test_ppt_slide_layout(self):
        assert assign_role("ppt/slideLayouts/slideLayout1.xml") == OoxmlRole.slide_layout

    def test_media_path(self):
        assert assign_role("word/media/image1.png") == OoxmlRole.media

    def test_embeddings_path(self):
        assert assign_role("xl/embeddings/oleObject1.bin") == OoxmlRole.embedded_object

    def test_unknown_path(self):
        assert assign_role("some/random/file.xyz") == OoxmlRole.unknown

    def test_case_insensitive(self):
        # paths are lowercased internally
        assert assign_role("DOCPROPS/CORE.XML") == OoxmlRole.metadata

    def test_word_comments(self):
        assert assign_role("word/comments.xml") == OoxmlRole.comment


class TestEnumerateStructure:
    def test_returns_all_paths(self):
        paths = ["[Content_Types].xml", "_rels/.rels", "word/document.xml"]
        result = enumerate_structure(paths)
        assert set(result.keys()) == set(paths)

    def test_empty_list(self):
        assert enumerate_structure([]) == {}

    def test_role_values_are_ooxml_role(self):
        paths = ["xl/worksheets/sheet1.xml", "docProps/core.xml"]
        result = enumerate_structure(paths)
        for role in result.values():
            assert isinstance(role, OoxmlRole)
