#!/usr/bin/env python3
"""
API Documentation Generator for Vrindha SOC.

Generates Markdown API documentation from the FastAPI application.
Run with: python scripts/generate_api_docs.py
Output: docs/API.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add repo root to path
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from vrin_SOC.api.main import app


def generate_markdown() -> str:
    """Generate Markdown documentation from the FastAPI OpenAPI schema."""
    openapi = app.openapi()

    lines = [
        "# Vrindha AI SOC API Documentation",
        "",
        f"**Version:** {openapi.get('info', {}).get('version', '1.0.0')}",
        f"**Title:** {openapi.get('info', {}).get('title', 'Vrindha AI SOC System')}",
        f"**Description:** {openapi.get('info', {}).get('description', '')}",
        "",
        "---",
        "",
    ]

    paths = openapi.get("paths", {})
    # Group by tag
    tags_order = [
        "auth", "coordination", "blockchain", "hive", "red-team",
        "threat-intelligence", "teams", "ml", "autonomy"
    ]
    tag_sections = {tag: [] for tag in tags_order}
    tag_sections["other"] = []

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                continue
            tags = details.get("tags", ["other"])
            primary_tag = tags[0] if tags else "other"
            if primary_tag not in tag_sections:
                primary_tag = "other"
            tag_sections[primary_tag].append((path, method.upper(), details))

    for tag in tags_order + ["other"]:
        endpoints = tag_sections.get(tag, [])
        if not endpoints:
            continue
        lines.append(f"## {tag.replace('-', ' ').title()}")
        lines.append("")
        for path, method, details in sorted(endpoints, key=lambda x: x[0]):
            summary = details.get("summary", "")
            desc = details.get("description", "")
            lines.append(f"### {method} `{path}`")
            if summary:
                lines.append(f"**Summary:** {summary}")
            if desc:
                lines.append(f"**Description:** {desc}")
            # Parameters
            params = details.get("parameters", [])
            if params:
                lines.append("")
                lines.append("**Parameters:**")
                for p in params:
                    pname = p.get("name", "")
                    pin = p.get("in", "")
                    preq = "required" if p.get("required") else "optional"
                    pdesc = p.get("description", "")
                    lines.append(f"- `{pname}` ({pin}, {preq}): {pdesc}")
            # Request body
            req_body = details.get("requestBody", {})
            if req_body:
                lines.append("")
                lines.append("**Request Body:**")
                content = req_body.get("content", {})
                for media_type, schema_info in content.items():
                    schema = schema_info.get("schema", {})
                    lines.append(f"- Content-Type: `{media_type}`")
                    if "$ref" in schema:
                        lines.append(f"  - Schema: `{schema['$ref'].split('/')[-1]}`")
            # Responses
            responses = details.get("responses", {})
            if responses:
                lines.append("")
                lines.append("**Responses:**")
                for code, resp in responses.items():
                    desc = resp.get("description", "")
                    lines.append(f"- `{code}`: {desc}")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    output_path = _REPO_ROOT / "docs" / "API.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    markdown = generate_markdown()
    output_path.write_text(markdown, encoding="utf-8")
    print(f"[generate_api_docs] Written {len(markdown)} chars to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())