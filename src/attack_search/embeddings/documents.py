"""Build deterministic semantic documents and PostgreSQL back-references."""

from collections import defaultdict
from uuid import NAMESPACE_URL, uuid5

from attack_search.embeddings.profile import (
    CHUNK_BYTES,
    DIMENSIONS,
    MODEL,
    NODE_TYPES,
    PIPELINE_VERSION,
)
from attack_search.embeddings.text import clean_text, split_text
from attack_search.fingerprints import digest


def active(row: dict) -> bool:
    return not row.get("revoked", False) and not row.get("deprecated", False)


def build_documents(tables: dict, snapshot: str) -> list[dict]:
    nodes = {n["id"]: n for n in tables["nodes"]}
    dataset_versions = sorted(
        {
            n["stix_json"]["x_mitre_version"]
            for n in nodes.values()
            if n["type"] == "x-mitre-collection" and n["stix_json"].get("x_mitre_version")
        }
    )
    tactics, analytics, strategies, components = (defaultdict(list) for _ in range(4))
    related, active_related, parents = defaultdict(set), defaultdict(set), {}
    for row in tables["technique_tactics"]:
        tactics[row["technique_id"]].append(row["tactic_id"])
    for row in tables["strategy_analytics"]:
        analytics[row["strategy_id"]].append(row["analytic_id"])
        strategies[row["analytic_id"]].append(row["strategy_id"])
    for row in tables["analytic_data_components"]:
        components[row["analytic_id"]].append(row["data_component_id"])
    for rel in tables["relationships"]:
        source, target = rel["source_id"], rel["target_id"]
        if rel["relationship_type"] in {"mitigates", "detects"}:
            if nodes[target]["type"] != "attack-pattern":
                raise ValueError("Expected technique target on mitigates/detects")
            related[source].add(target)
            if active(rel) and active(nodes[source]) and active(nodes[target]):
                active_related[source].add(target)
        elif rel["relationship_type"] == "subtechnique-of" and active(rel):
            parents[source] = target
    for analytic_id, strategy_ids in strategies.items():
        for strategy_id in strategy_ids:
            related[analytic_id].update(related[strategy_id])
            if active(nodes[analytic_id]):
                active_related[analytic_id].update(active_related[strategy_id])

    def metadata(row, table, kind, technique_ids, active_techniques):
        technique_ids = sorted(set(technique_ids))
        raw = row.get("stix_json", {})
        tactic_ids = sorted({t for key in technique_ids for t in tactics[key]})
        payload = {
            "type": kind,
            "db_schema": "attack",
            "db_table": table,
            "db_id": str(row["id"]),
            "document_id": f"attack.{table}:{row['id']}",
            "dataset_snapshot": snapshot,
            "pipeline_version": PIPELINE_VERSION,
            "dataset_versions": dataset_versions,
            "embedding_model": MODEL,
            "embedding_dimensions": DIMENSIONS,
            "language": "en",
            "domain": "enterprise-attack",
            "technique_ids": technique_ids,
            "technique_attack_ids": [nodes[t]["attack_id"] for t in technique_ids],
            "technique_names": [nodes[t]["name"] for t in technique_ids],
            "active_technique_ids": sorted(set(active_techniques)),
            "related_tactic_ids": tactic_ids,
            "related_tactic_attack_ids": [nodes[t]["attack_id"] for t in tactic_ids],
            "related_platforms": sorted(
                {
                    p
                    for t in technique_ids
                    for p in nodes[t]["stix_json"].get("x_mitre_platforms", [])
                }
            ),
            "is_active": active(row),
        }
        if table != "behavior_examples":
            payload.update(
                revoked=row["revoked"],
                deprecated=row["deprecated"],
                stix_type=raw.get("type"),
                created=raw.get("created"),
                modified=raw.get("modified"),
                object_version=raw.get("x_mitre_version"),
                source_urls=[r["url"] for r in raw.get("external_references", []) if r.get("url")],
            )
        if table == "nodes":
            payload.update(
                name=row["name"],
                attack_id=row["attack_id"],
                platforms=raw.get("x_mitre_platforms", []),
            )
        return payload

    documents = []

    def add(payload, title, segments):
        # A segment is (actual source text, provenance fields).
        pieces = [(part, provenance) for text, provenance in segments for part in split_text(text)]
        for index, (text, provenance) in enumerate(pieces):
            embedding_text = f"title: {title or 'none'} | text: {text}"
            if len(embedding_text.encode()) > 7000:
                raise ValueError("Embedding input exceeds the conservative byte budget")
            point_payload = {
                **payload,
                **provenance,
                "title": title,
                "text": text,
                "embedding_text": embedding_text,
                "chunk_index": index,
                "chunk_count": len(pieces),
                "content_hash": digest(embedding_text),
            }
            key = [
                snapshot,
                MODEL,
                DIMENSIONS,
                PIPELINE_VERSION,
                CHUNK_BYTES,
                payload["document_id"],
                index,
                point_payload["content_hash"],
            ]
            documents.append(
                {"id": str(uuid5(NAMESPACE_URL, digest(key))), "payload": point_payload}
            )

    for node in tables["nodes"]:
        kind, key = node["type"], node["id"]
        if kind not in NODE_TYPES:
            continue
        tids = {key} if kind == "attack-pattern" else related[key]
        active_tids = (
            ({key} if active(node) else set()) if kind == "attack-pattern" else active_related[key]
        )
        payload = metadata(node, "nodes", kind, tids, active_tids)
        title = clean_text(node["name"])
        description = clean_text(node["description"])
        segments = [
            (description or title, {"text_origin": "description" if description else "title_only"})
        ]
        if kind == "attack-pattern":
            parent = nodes.get(parents.get(key))
            payload.update(
                is_subtechnique=node["stix_json"].get("x_mitre_is_subtechnique", False),
                parent_id=parent["id"] if parent else None,
                parent_attack_id=parent["attack_id"] if parent else None,
                parent_name=parent["name"] if parent else None,
            )
            if parent:
                title = f"{clean_text(parent['name'])}: {title}"
        elif kind == "x-mitre-detection-strategy":
            payload["analytic_ids"] = sorted(analytics[key])
            if not description:
                derived = []
                for aid in sorted(analytics[key]):
                    body = clean_text(nodes[aid]["description"])
                    if body:
                        derived.append(
                            (
                                body,
                                {
                                    "text_origin": "linked_analytics",
                                    "context_analytic_ids": [aid],
                                    "is_active": active(node) and active(nodes[aid]),
                                },
                            )
                        )
                if derived:
                    segments = derived
        elif kind == "x-mitre-analytic":
            payload.update(
                strategy_ids=sorted(strategies[key]),
                data_component_ids=sorted(components[key]),
                log_sources=node["stix_json"].get("x_mitre_log_source_references", []),
                mutable_elements=node["stix_json"].get("x_mitre_mutable_elements", []),
            )
            context = "; ".join(clean_text(nodes[s]["name"]) for s in sorted(strategies[key]))
            title = f"{context}: {title}" if context else title
        add(payload, title, segments)

    for row in tables["behavior_examples"]:
        technique = nodes[row["technique_id"]]
        text = clean_text(row["text"])
        if not text:
            raise ValueError(f"Behavior example {row['id']} is empty after cleaning")
        tids = [technique["id"]]
        payload = metadata(
            row, "behavior_examples", "behavior_example", tids, tids if active(technique) else []
        )
        payload.update(
            is_active=active(technique),
            technique_revoked=technique["revoked"],
            technique_deprecated=technique["deprecated"],
        )
        add(payload, None, [(text, {"text_origin": "description"})])

    for row in tables["relationships"]:
        if row["relationship_type"] != "mitigates":
            continue  # detects remains a PostgreSQL link, not an independent vector.
        source, target = nodes[row["source_id"]], nodes[row["target_id"]]
        is_active = active(row) and active(source) and active(target)
        payload = metadata(
            row, "relationships", "mitigates", [target["id"]], [target["id"]] if is_active else []
        )
        payload.update(relationship_type="mitigates", is_active=is_active)
        for prefix, endpoint in (("source", source), ("target", target)):
            for field in ("id", "attack_id", "type", "name", "revoked", "deprecated"):
                payload[f"{prefix}_{field}"] = endpoint[field]
        title = f"{clean_text(source['name'])} mitigates {clean_text(target['name'])}"
        text = clean_text(row["description"])
        add(
            payload,
            title,
            [(text or title, {"text_origin": "description" if text else "title_only"})],
        )
    return documents
