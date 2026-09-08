"""OpenRouter embeddings adapter; no requests are made on import."""

import math
import os

from openai import OpenAI

from attack_search.embeddings.profile import DIMENSIONS, MODEL


def create_embedding_client() -> OpenAI:
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ["OPENROUTER_API_KEY"],
        timeout=60,
        max_retries=2,
    )


def embed_batch(client, texts: list[str]) -> list[list[float]]:
    response = client.embeddings.create(
        model=MODEL, input=texts, dimensions=DIMENSIONS, encoding_format="float"
    )
    data = sorted(response.data, key=lambda item: item.index)
    if [item.index for item in data] != list(range(len(texts))):
        raise ValueError("Embedding response count/indices do not match inputs; refusing to upload")
    vectors = [item.embedding for item in data]
    for vector in vectors:
        if (
            len(vector) != DIMENSIONS
            or not all(math.isfinite(v) for v in vector)
            or not any(vector)
        ):
            raise ValueError("Invalid embedding dimension, non-finite value, or zero vector")
    return vectors


def embed_query(client, query: str, *, question_answering: bool = False) -> list[float]:
    task = "question answering" if question_answering else "search result"
    return embed_batch(client, [f"task: {task} | query: {query}"])[0]
