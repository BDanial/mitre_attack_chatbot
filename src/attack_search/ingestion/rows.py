"""Convert filtered STIX and behavior examples into relational rows."""

from psycopg.types.json import Jsonb

from attack_search.storage.postgres import TABLE_COLUMNS


def get_attack_id(node: dict) -> str | None:
    for reference in node.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def prepare_tables(bundle: dict, examples: list[dict]) -> dict[str, list[tuple]]:
    """Resolve JSON references before starting the database transaction."""
    nodes = [obj for obj in bundle["objects"] if obj["type"] != "relationship"]
    relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
    by_id = {node["id"]: node for node in nodes}
    technique_ids = {
        get_attack_id(node): node["id"] for node in nodes if node["type"] == "attack-pattern"
    }
    tactic_ids = {
        node["x_mitre_shortname"]: node["id"] for node in nodes if node["type"] == "x-mitre-tactic"
    }

    def require_type(node_id: str, expected_type: str) -> str:
        if node_id not in by_id or by_id[node_id]["type"] != expected_type:
            raise ValueError(f"Expected {expected_type} node: {node_id}")
        return node_id

    rows = {table: [] for table in TABLE_COLUMNS}
    rows["nodes"] = [
        (
            node["id"],
            get_attack_id(node),
            node["type"],
            node.get("name"),
            node.get("description"),
            node.get("x_mitre_deprecated", False),
            node.get("revoked", False),
            Jsonb(node),
        )
        for node in nodes
    ]
    rows["relationships"] = [
        (
            rel["id"],
            rel["source_ref"],
            rel["target_ref"],
            rel["relationship_type"],
            rel.get("description"),
            rel.get("x_mitre_deprecated", False),
            rel.get("revoked", False),
            Jsonb(rel),
        )
        for rel in relationships
    ]
    rows["behavior_examples"] = [
        (index, technique_ids[example["node_id"]], example["text"])
        for index, example in enumerate(examples, start=1)
    ]

    for node in nodes:
        node_id = node["id"]
        if node["type"] == "attack-pattern":
            for phase in node.get("kill_chain_phases", []):
                if phase["kill_chain_name"] == "mitre-attack":
                    rows["technique_tactics"].append((node_id, tactic_ids[phase["phase_name"]]))
        elif node["type"] == "x-mitre-detection-strategy":
            for ref in node.get("x_mitre_analytic_refs", []):
                rows["strategy_analytics"].append((node_id, require_type(ref, "x-mitre-analytic")))
        elif node["type"] == "x-mitre-analytic":
            for ref in node.get("x_mitre_log_source_references", []):
                component_id = require_type(
                    ref["x_mitre_data_component_ref"], "x-mitre-data-component"
                )
                rows["analytic_data_components"].append((node_id, component_id))
        elif node["type"] == "x-mitre-matrix":
            for position, ref in enumerate(node.get("tactic_refs", []), start=1):
                rows["matrix_tactics"].append(
                    (node_id, require_type(ref, "x-mitre-tactic"), position)
                )

    # Multiple log sources may refer to the same analytic/component pair.
    for table in ("technique_tactics", "strategy_analytics", "analytic_data_components"):
        rows[table] = sorted(set(rows[table]))
    return rows
