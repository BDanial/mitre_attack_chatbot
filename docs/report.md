# ATT&CK Retrieval — Project Report

**Review date:** 7 September 2026  
**Stage:** SQL and semantic/lexical/hybrid retrieval backend (v0.2)

**Audience:** Technical reviewers and future maintainers

> Implementation update — 8 September 2026: the two FastAPI search tools are now implemented
> with API-key authentication. Public deployment and the Dify chatbot remain future work.
> See the [API guide](api.md) for the current interface and security limits. This report describes
> the data foundations, current retrieval backend, and separately dated earlier checks.

> Version 0.2 implementation update: `search_attack` now supports semantic, lexical BM25 and
> hybrid retrieval with LLM-selected weights and simple filters. The backend combines the two
> Qdrant rankings using weighted reciprocal rank fusion. `index-lexical` upgrades the existing
> collection additively without recomputing dense embeddings. See the [API guide](api.md),
> [operations](operations.md), and [LLM guide](orchestrator/llm-tool-guide.md).
> The historical verification section retains its original review results; current capabilities
> and remaining deployment work are described separately below.

## Purpose

Security users often describe an action without knowing its ATT&CK name. For example, they may
write “run encoded commands with PowerShell.” This project prepares data that can connect that
description to the right technique, its detection guidance, and its mitigations.

The source is MITRE Enterprise ATT&CK in STIX format. MITRE also uses STIX data to build its
website and other data views. [MITRE data reference](https://attack.mitre.org/resources/attack-data-and-tools/)

This report provides design and dated verification context. For tool calls, follow the
[documentation map](README.md), [LLM guide](orchestrator/llm-tool-guide.md), and [API contract](api.md).
Dated counts and earlier results are not live answers to user questions.

## What works today

The project downloads and filters ATT&CK data, stores its relationships in PostgreSQL, and creates
dense semantic and sparse BM25 indexes in Qdrant. It uses Google Gemini Embedding 2 through
OpenRouter for dense vectors and native Qdrant BM25 for lexical retrieval. FastAPI exposes
`query_sql` and `search_attack`; the LLM chooses mode and relative hybrid weights. The command-line
tools support progress output, sample runs, and resume after a failed upload.

Group, campaign, malware, and tool nodes are removed from the graph. Before this step, the code
keeps the descriptions of `uses` relationships that point to techniques. These become behavior
examples. Each example keeps its technique connection, so it remains useful for retrieval.

## How the parts work together

```mermaid
flowchart LR
    A[MITRE STIX JSON] --> B[Filter and prepare]
    B --> P[(PostgreSQL: source and relationships)]
    P --> C[Clean text and build chunks]
    C --> E[OpenRouter: Gemini embeddings]
    E --> Q[(Qdrant: vectors and metadata)]
    C --> B25[Native BM25]
    B25 --> Q
    D[Dify chatbot: planned] -. tools .-> F[FastAPI tools]
    F -->|Semantic / lexical / hybrid| Q
    F -->|Read-only SQL| P
    F -->|Semantic or hybrid query embedding| E
```

*Solid arrows show implemented backend paths. The dashed Dify integration remains planned.*

PostgreSQL is the main source of truth. Qdrant helps find relevant text. Every point carries its
type, source table, database ID, and related technique IDs. This makes it possible to return from
a search result to the original record. The two schemas are documented in the appendices.

## Main design choices

The code uses a `src/attack_search` package. Data preparation, embedding calls, database access,
and application workflows have separate modules. A single `attack-search` command runs the jobs.
This structure follows the purpose of Python's `src` layout: imported application code belongs
to an installed package. [Python packaging guide](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)

Behavior examples use only clean description text with the model's required document prefix.
Metadata stays beside the vector. Detection strategies use real descriptions from linked
analytics when their own description is empty. `detects` stays a database relationship;
`mitigates` has its own point because its description gives technique-specific advice.

Each index belongs to a specific source snapshot and embedding profile. A complete index is
published through the alias `attack_semantic`. This helps prevent an unfinished upload from
becoming the normal search target. PostgreSQL and Qdrant still need a coordinated refresh.

## Historical data-pipeline checks (7 September 2026)

These results describe the original pipeline review. The v0.2 upgrade subsequently passed
225 offline tests and live SQL/semantic/lexical/hybrid smoke checks; see [API verification](api.md#6-tests).

| Measure | Verified result |
| --- | ---: |
| ATT&CK release | 19.2 |
| PostgreSQL tables / views | 7 / 12 |
| Behavior examples | 17,136 |
| Qdrant points | 23,240 |
| Vector dimensions | 3,072 |
| Offline tests passed | 26 |

Before and after the refactor, the STIX filter output, prepared SQL rows, and all semantic
document IDs and payloads matched exactly. Automated tests cover text cleaning, reference
handling, vector validation, local Qdrant uploads, resume, and publication checks.
All 22 SQL examples in Appendix A also ran successfully in a read-only transaction.

Earlier English and Persian PowerShell search checks both returned `T1059.001` first among
active techniques. These are small checks, not a full quality benchmark. During the first
upload, a Qdrant 507 error stopped one run. A later run completed from the saved points.

## Next stages

FastAPI authentication, request validation, guarded read-only SQL, limits, timeouts, and the
three search modes are implemented. Public hosting and a configured Dify chatbot remain separate
work. Connect Dify using the current OpenAPI operation IDs `query_sql` and `search_attack`;
see [API and Dify setup](api.md).

Before public exposure, configure a least-privilege database role, HTTPS, rate/concurrency limits,
and deployment-level request/response limits. Evaluate realistic multilingual questions and
retrieval quality; existing smoke checks are not a benchmark. The database stores one snapshot,
and behavior IDs can change after an import. Coordinate refreshes before joining search results
to source rows; see [operations](operations.md#refresh-a-published-snapshot).

## Appendices

- [Appendix A — PostgreSQL schema and Text-to-SQL reference](appendices/postgresql.md):
  every table, column, key, relationship, view and index, with 22 SQL examples.
- [Appendix B — Qdrant storage schema](appendices/qdrant.md):
  vector configuration, point identity, every payload field and the PostgreSQL mapping.
- [Operations guide](operations.md): installation, commands, refresh, recovery and verification.
