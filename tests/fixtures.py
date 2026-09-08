"""Small synthetic STIX-shaped records used across tests."""

from attack_search.storage.postgres import TABLE_COLUMNS


def node(kind, suffix, name, description=None, **stix):
    return {
        "id": f"{kind}--{suffix}",
        "type": kind,
        "name": name,
        "attack_id": suffix,
        "description": description,
        "revoked": False,
        "deprecated": False,
        "stix_json": {"type": kind, **stix},
    }


def fixture():
    tables = {key: [] for key in TABLE_COLUMNS}
    parent = node(
        "attack-pattern", "T1059", "Command and Scripting Interpreter", "Execute scripts."
    )
    technique = node(
        "attack-pattern",
        "T1059.001",
        "PowerShell",
        "Execute commands.",
        x_mitre_is_subtechnique=True,
        x_mitre_platforms=["Windows"],
    )
    mitigation = node("course-of-action", "M1038", "Execution Prevention", "Control execution.")
    strategy = node("x-mitre-detection-strategy", "DET1", "Detect PowerShell abuse")
    analytic = node("x-mitre-analytic", "AN1", "Analytic 1", "Look for encoded commands.")
    tables["nodes"] = [parent, technique, mitigation, strategy, analytic]
    for index, (source, target, kind, text) in enumerate(
        [
            (technique, parent, "subtechnique-of", None),
            (mitigation, technique, "mitigates", "Restrict script execution.(Citation: Reference)"),
            (strategy, technique, "detects", None),
        ]
    ):
        tables["relationships"].append(
            {
                "id": f"relationship--{index}",
                "source_id": source["id"],
                "target_id": target["id"],
                "relationship_type": kind,
                "description": text,
                "deprecated": False,
                "revoked": False,
                "stix_json": {"type": "relationship"},
            }
        )
    tables["strategy_analytics"] = [{"strategy_id": strategy["id"], "analytic_id": analytic["id"]}]
    tables["behavior_examples"] = [
        {
            "id": 42,
            "technique_id": technique["id"],
            "text": "[Actor](https://example.com) used `powershell.exe -enc`.(Citation: Ref)",
        }
    ]
    return tables
