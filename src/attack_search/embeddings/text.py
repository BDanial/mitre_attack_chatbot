"""Clean ATT&CK markup and split text without generated summaries."""

import re
from html.parser import HTMLParser

from markdown_it import MarkdownIt

from attack_search.embeddings.profile import CHUNK_BYTES

MARKDOWN = MarkdownIt("commonmark").enable("table")


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def clean_text(raw: str | None) -> str:
    """Remove reference markup; preserve visible names, commands, paths and code."""
    parts = []
    for block in MARKDOWN.parse(raw or ""):
        if block.type == "inline":
            inline = []
            for token in block.children or []:
                if token.type == "text":
                    inline.append(re.sub(r"\(Citation:[^)]*\)", "", token.content))
                elif token.type == "code_inline":
                    inline.append(token.content)
                elif token.type in {"softbreak", "hardbreak"}:
                    inline.append(" ")
                elif token.type == "image":
                    inline.append(token.content)
                elif token.type == "html_inline" and re.match(r"<br\b", token.content, re.I):
                    inline.append(" ")
            parts.append("".join(inline))
        elif block.type in {"fence", "code_block"}:
            parts.append(block.content)
        elif block.type == "html_block":
            parser = PlainHTML()
            parser.feed(block.content)
            parts.append(" ".join(parser.parts))
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def split_text(text: str, max_bytes: int = CHUNK_BYTES) -> list[str]:
    """Prefer sentence boundaries, then spaces; never discard a long code token."""
    chunks, current = [], ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        units = [sentence] if len(sentence.encode()) <= max_bytes else sentence.split()
        for unit in units:
            # Hard split only pathological uninterrupted strings.
            fragments, fragment = [], ""
            for char in unit:
                if len((fragment + char).encode()) > max_bytes:
                    fragments.append(fragment)
                    fragment = ""
                fragment += char
            if fragment:
                fragments.append(fragment)
            for fragment in fragments:
                candidate = f"{current} {fragment}".strip()
                if current and len(candidate.encode()) > max_bytes:
                    chunks.append(current)
                    current = fragment
                else:
                    current = candidate
    if current:
        chunks.append(current)
    return chunks
