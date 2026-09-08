"""LLM-facing retrieval inputs shared by the API and service layer."""

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SearchMode = Literal["semantic", "lexical", "hybrid"]
EvidenceType = Literal[
    "attack-pattern",
    "behavior_example",
    "course-of-action",
    "mitigates",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
]
TechniqueCode = Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
PlatformName = Annotated[str, Field(min_length=1, max_length=100)]


class SearchWeights(BaseModel):
    """Positive relative contributions to rank fusion, never raw-score multipliers."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    semantic: float = Field(gt=0, strict=True, description="Semantic rank weight, e.g. 0.7.")
    lexical: float = Field(gt=0, strict=True, description="Lexical rank weight, e.g. 0.3.")

    @model_validator(mode="after")
    def validate_ratio(self):
        if min(self.semantic, self.lexical) / max(self.semantic, self.lexical) == 0:
            raise ValueError("Weight ratio is too extreme; use two representable positive weights")
        return self

    def normalized(self) -> dict[str, float]:
        # Scale before summing so even very large finite relative weights remain valid.
        scale = max(self.semantic, self.lexical)
        semantic, lexical = self.semantic / scale, self.lexical / scale
        total = semantic + lexical
        return {"semantic": semantic / total, "lexical": lexical / total}


class SearchFilters(BaseModel):
    """Small typed filters: callers never need to construct Qdrant conditions."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    is_active: bool | None = Field(
        default=True, strict=True, description="true: active; false: inactive; null: all statuses."
    )
    types: list[EvidenceType] | None = Field(
        default=None,
        min_length=1,
        max_length=6,
        description="Evidence types to include. Omit for all types; do not send an empty list.",
    )
    technique_attack_ids: list[TechniqueCode] | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Related technique codes such as T1059.001; OR within the list.",
    )
    platforms: list[PlatformName] | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Related technique platforms, e.g. Windows. Exact spelling; OR within list.",
    )

    def to_qdrant_filter(self) -> dict:
        conditions = []
        if self.is_active is not None:
            conditions.append({"key": "is_active", "match": {"value": self.is_active}})
        for key, values in (
            ("type", self.types),
            ("technique_attack_ids", self.technique_attack_ids),
            ("related_platforms", self.platforms),
        ):
            if values is not None:
                conditions.append({"key": key, "match": {"any": list(dict.fromkeys(values))}})
        return {"must": conditions} if conditions else {}


SEARCH_EXAMPLES = [
    {
        "mode": "semantic",
        "query": "An attacker runs encoded commands using PowerShell",
        "filters": {"types": ["attack-pattern", "behavior_example"]},
        "limit": 5,
    },
    {"mode": "lexical", "query": "powershell -EncodedCommand", "limit": 5},
    {
        "mode": "hybrid",
        "query": "اجرای دستورات رمزگذاری‌شده با پاورشل",
        "lexical_query": "powershell -EncodedCommand",
        "weights": {"semantic": 0.7, "lexical": 0.3},
        "filters": {"types": ["attack-pattern", "behavior_example"], "platforms": ["Windows"]},
        "limit": 5,
    },
]


class SearchRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        revalidate_instances="always",
        json_schema_extra={"examples": SEARCH_EXAMPLES},
    )

    mode: SearchMode = Field(description="semantic: meaning; lexical: words; hybrid: both.")
    query: str = Field(
        min_length=1,
        max_length=7000,
        description="Raw search text. In lexical mode use corpus-language words (English).",
    )
    lexical_query: str | None = Field(
        default=None,
        min_length=1,
        max_length=7000,
        description="Hybrid only: optional English words/commands for BM25; otherwise query is used.",
    )
    weights: SearchWeights | None = Field(
        default=None,
        description="Required for hybrid; omit in other modes. Positive relative weights, e.g. "
        '{"semantic":0.7,"lexical":0.3}. Applied to ranks, not raw scores.',
    )
    filters: SearchFilters = Field(
        default_factory=SearchFilters,
        description="Simple fields only; no Qdrant syntax. Omitted or {} means active records.",
    )
    limit: int = Field(default=10, ge=1, le=50, strict=True)
    offset: int = Field(default=0, ge=0, le=1000, strict=True)
    question_answering: bool = Field(
        default=False,
        strict=True,
        description="Semantic/hybrid only: change the embedding task prefix; does not select a mode.",
    )

    @field_validator("filters", "weights", mode="before")
    @classmethod
    def parse_object_string(cls, value):
        # Dify tool clients may serialize nested object arguments as JSON strings.
        return json.loads(value) if isinstance(value, str) else value

    @field_validator("query", "lexical_query")
    @classmethod
    def bound_utf8(cls, value):
        if value is not None and len(value.encode("utf-8")) > 7000:
            raise ValueError("Search text must be at most 7000 UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def validate_mode(self):
        if self.mode == "hybrid":
            if self.weights is None:
                raise ValueError("Hybrid mode requires weights with semantic and lexical values")
        elif self.weights is not None or self.lexical_query is not None:
            raise ValueError("weights and lexical_query are allowed only in hybrid mode")
        if self.mode == "lexical" and self.question_answering:
            raise ValueError("question_answering is not used in lexical mode; omit it or use false")
        return self
