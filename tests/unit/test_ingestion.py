from copy import deepcopy

import pytest

from attack_search.ingestion.rows import prepare_tables
from attack_search.ingestion.stix import prepare_data


def test_uses_description_survives_removal_of_its_source():
    technique = {
        "id": "attack-pattern--example",
        "type": "attack-pattern",
        "name": "PowerShell",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
    }
    actor = {"id": "intrusion-set--example", "type": "intrusion-set"}
    use = {
        "id": "relationship--example",
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": actor["id"],
        "target_ref": technique["id"],
        "description": "Actor used  PowerShell.\n",
    }
    source = {"type": "bundle", "objects": [actor, technique, use]}
    original = deepcopy(source)
    bundle, examples = prepare_data(source)

    assert source == original
    assert bundle["objects"] == [technique]
    assert examples == [
        {"node_id": "T1059.001", "chunk_type": "behavior_example", "text": "Actor used PowerShell."}
    ]
    assert prepare_tables(bundle, examples)["behavior_examples"] == [
        (1, technique["id"], "Actor used PowerShell.")
    ]


def test_invalid_analytic_component_reference_fails_before_database_write():
    bundle = {
        "objects": [
            {
                "id": "x-mitre-analytic--example",
                "type": "x-mitre-analytic",
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "attack-pattern--wrong-type"}
                ],
            }
        ]
    }
    with pytest.raises(ValueError, match="Expected x-mitre-data-component"):
        prepare_tables(bundle, [])
