import unittest

from attack_search.embeddings.documents import build_documents
from attack_search.embeddings.profile import collection_name
from tests.fixtures import fixture


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.tables = fixture()
        self.documents = build_documents(self.tables, "snapshot")

    def payload(self, kind):
        return next(d["payload"] for d in self.documents if d["payload"]["type"] == kind)

    def test_types_and_real_tables(self):
        self.assertEqual(
            {d["payload"]["type"] for d in self.documents},
            {
                "attack-pattern",
                "behavior_example",
                "course-of-action",
                "x-mitre-detection-strategy",
                "x-mitre-analytic",
                "mitigates",
            },
        )
        self.assertEqual(self.payload("x-mitre-analytic")["db_table"], "nodes")
        self.assertEqual(self.payload("mitigates")["db_table"], "relationships")

    def test_behavior_no_title_or_synthetic_status(self):
        p = self.payload("behavior_example")
        self.assertEqual(p["db_id"], "42")
        self.assertEqual(p["technique_attack_ids"], ["T1059.001"])
        self.assertEqual(p["embedding_text"], "title: none | text: Actor used powershell.exe -enc.")
        self.assertNotIn("revoked", p)

    def test_parent(self):
        p = next(
            d["payload"]
            for d in self.documents
            if d["payload"]["db_id"] == "attack-pattern--T1059.001"
        )
        self.assertTrue(p["is_subtechnique"])
        self.assertEqual(p["parent_attack_id"], "T1059")

    def test_strategy_uses_actual_analytic_and_keeps_provenance(self):
        p = self.payload("x-mitre-detection-strategy")
        self.assertEqual(p["text"], "Look for encoded commands.")
        self.assertEqual(p["text_origin"], "linked_analytics")
        self.assertEqual(p["context_analytic_ids"], ["x-mitre-analytic--AN1"])
        self.assertEqual(self.payload("x-mitre-analytic")["technique_attack_ids"], ["T1059.001"])

    def test_no_analytic_fallback(self):
        self.tables["strategy_analytics"] = []
        p = next(
            d["payload"]
            for d in build_documents(self.tables, "snapshot")
            if d["payload"]["type"] == "x-mitre-detection-strategy"
        )
        self.assertEqual(p["text_origin"], "title_only")

    def test_status_and_relationship_target(self):
        self.tables["nodes"][1]["revoked"] = True
        docs = build_documents(self.tables, "snapshot")
        for kind in ["behavior_example", "mitigates"]:
            p = next(d["payload"] for d in docs if d["payload"]["type"] == kind)
            self.assertFalse(p["is_active"])
            self.assertEqual(p["active_technique_ids"], [])

    def test_identity_and_snapshot(self):
        self.assertEqual(self.documents, build_documents(self.tables, "snapshot"))
        newer = build_documents(self.tables, "new-snapshot")
        self.assertFalse({d["id"] for d in self.documents} & {d["id"] for d in newer})
        self.assertNotEqual(collection_name("snapshot"), collection_name("new-snapshot"))
        self.assertEqual(len({d["id"] for d in self.documents}), len(self.documents))

    def test_empty_behavior_is_reported(self):
        self.tables["behavior_examples"][0]["text"] = "(Citation: Only a reference)"
        with self.assertRaises(ValueError):
            build_documents(self.tables, "snapshot")
