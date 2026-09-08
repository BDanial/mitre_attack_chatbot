import unittest

from attack_search.embeddings.text import clean_text, split_text


class TextTests(unittest.TestCase):
    def test_links_citations_and_code(self):
        self.assertEqual(
            clean_text("[Actor](https://example.com/a_(b)) used `pwsh -enc`.(Citation: Ref)"),
            "Actor used pwsh -enc.",
        )

    def test_html_and_entities(self):
        self.assertEqual(
            clean_text("<b>PowerShell</b><br>scripts &amp; commands"),
            "PowerShell scripts & commands",
        )

    def test_preserve_technical_content(self):
        self.assertEqual(
            clean_text("`C:\\Windows\\a.exe` `HKLM\\Software` `curl https://host/payload`"),
            "C:\\Windows\\a.exe HKLM\\Software curl https://host/payload",
        )

    def test_reference_links(self):
        self.assertEqual(
            clean_text("[PowerShell][ps] runs.\n\n[ps]: https://example.com"), "PowerShell runs."
        )

    def test_unicode_chunk_budget(self):
        chunks = split_text("متن آزمایشی. " * 100, 90)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c.encode()) <= 90 for c in chunks))
        self.assertEqual(" ".join(chunks), ("متن آزمایشی. " * 100).strip())

    def test_long_unbroken_text_not_lost(self):
        chunks = split_text("x" * 100, 30)
        self.assertEqual("".join(chunks), "x" * 100)
