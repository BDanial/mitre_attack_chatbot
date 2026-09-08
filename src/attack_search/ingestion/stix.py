"""Download and filter Enterprise STIX while retaining uses descriptions."""

import json
from pathlib import Path
from urllib.request import Request, urlopen

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

REMOVED_NODE_TYPES = {"intrusion-set", "campaign", "malware", "tool"}


def download_attack_data() -> dict:
    """Download the latest Enterprise ATT&CK STIX bundle."""
    request = Request(ATTACK_URL, headers={"User-Agent": "mitre-attack-search-demo"})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def attack_id(attack_pattern: dict) -> str | None:
    """Return an ATT&CK technique ID such as T1059.001."""
    for reference in attack_pattern.get("external_references", []):
        external_id = reference.get("external_id", "")
        if external_id.startswith("T"):
            return external_id
    return None


def prepare_data(bundle: dict) -> tuple[dict, list[dict]]:
    objects = bundle["objects"]

    techniques = {
        obj["id"]: attack_id(obj) for obj in objects if obj.get("type") == "attack-pattern"
    }

    # Extract useful search/training examples before removing their source nodes.
    behavior_examples = []
    for obj in objects:
        technique_id = techniques.get(obj.get("target_ref"))
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and technique_id
            and obj.get("description")
        ):
            behavior_examples.append(
                {
                    "node_id": technique_id,
                    "chunk_type": "behavior_example",
                    "text": " ".join(obj["description"].split()),
                }
            )

    removed_ids = {obj["id"] for obj in objects if obj.get("type") in REMOVED_NODE_TYPES}

    filtered_objects = []
    for obj in objects:
        if obj.get("id") in removed_ids:
            continue
        if obj.get("type") == "relationship" and (
            obj.get("source_ref") in removed_ids or obj.get("target_ref") in removed_ids
        ):
            continue
        filtered_objects.append(obj)

    filtered_bundle = {**bundle, "objects": filtered_objects}
    return filtered_bundle, behavior_examples


def save_json(path: Path, data: dict | list[dict]) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
