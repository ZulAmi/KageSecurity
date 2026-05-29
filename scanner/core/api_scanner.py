"""
Parses OpenAPI 3.x/Swagger 2.x specs and GraphQL introspection to produce
CrawlResult pages that feed directly into the existing module pipeline.
"""
import json
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanner.core.crawler import CrawlResult


# ─────────────────────────────────────────────────────────────────────────────
# OpenAPI / Swagger
# ─────────────────────────────────────────────────────────────────────────────

def scan_openapi(spec_url_or_path: str, base_url: str, client: httpx.Client) -> List[CrawlResult]:
    """
    Parse an OpenAPI 3.x or Swagger 2.x spec and generate one CrawlResult per
    endpoint × parameter combination. Each result has a synthetic form that the
    module pipeline can test just like a real HTML form.
    """
    spec = _load_spec(spec_url_or_path, client)
    if not spec:
        return []

    # Normalise base URL from spec servers / host fields
    if "servers" in spec and spec["servers"]:
        base = spec["servers"][0].get("url", base_url)
    elif "host" in spec:
        scheme = spec.get("schemes", ["https"])[0]
        base = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
    else:
        base = base_url

    pages: List[CrawlResult] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        url = urljoin(base, path)
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(operation, dict):
                continue

            inputs = _extract_inputs_from_operation(operation, spec)
            if not inputs:
                continue

            pages.append(CrawlResult(
                url=url,
                status_code=200,
                body="",
                forms=[{"method": method.lower(), "action": url, "inputs": inputs}],
                links=[],
                headers={},
            ))

    return pages


def _load_spec(spec_url_or_path: str, client: httpx.Client) -> Optional[dict]:
    try:
        parsed = urlparse(spec_url_or_path)
        if parsed.scheme in ("http", "https"):
            resp = client.get(spec_url_or_path, timeout=10)
            text = resp.text
        else:
            with open(spec_url_or_path) as f:
                text = f.read()

        # Try JSON first, then YAML
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import yaml  # type: ignore
            return yaml.safe_load(text)
    except Exception:
        return None


def _extract_inputs_from_operation(operation: dict, spec: dict) -> List[dict]:
    inputs = []

    # Path/query/header parameters
    for param in operation.get("parameters", []):
        if isinstance(param, dict) and "$ref" in param:
            param = _resolve_ref(param["$ref"], spec)
        if not param or not isinstance(param, dict):
            continue
        name = param.get("name", "")
        location = param.get("in", "query")
        if name and location in ("query", "path", "header"):
            example = _get_example(param)
            inputs.append({"name": name, "value": example, "type": "text"})

    # Request body (application/json or form)
    request_body = operation.get("requestBody", {})
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        for ct, ct_schema in content.items():
            schema = ct_schema.get("schema", {})
            if "$ref" in schema:
                schema = _resolve_ref(schema["$ref"], spec)
            for prop_name, prop_schema in schema.get("properties", {}).items():
                example = prop_schema.get("example", prop_schema.get("default", "test"))
                inputs.append({"name": prop_name, "value": str(example), "type": "text"})
            break  # use first content type only

    return inputs


def _get_example(param: dict) -> str:
    if "example" in param:
        return str(param["example"])
    schema = param.get("schema", {})
    if "example" in schema:
        return str(schema["example"])
    if "default" in schema:
        return str(schema["default"])
    return "1"  # safe default for most types


def _resolve_ref(ref: str, spec: dict) -> Optional[dict]:
    """Resolve a $ref like '#/components/schemas/Foo' from the spec."""
    try:
        parts = ref.lstrip("#/").split("/")
        node = spec
        for p in parts:
            node = node[p]
        return node
    except (KeyError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL
# ─────────────────────────────────────────────────────────────────────────────

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
"""


def scan_graphql(endpoint: str, client: httpx.Client) -> List[CrawlResult]:
    """
    Send an introspection query, then generate CrawlResult entries for each
    queryable / mutable string-argument field.
    """
    pages: List[CrawlResult] = []

    # Test if introspection is enabled — itself a finding trigger
    schema = _fetch_introspection(endpoint, client)
    if schema is None:
        return pages

    # Introspection-enabled finding (INFO — picked up by graphql.py module)
    pages.append(CrawlResult(
        url=endpoint,
        status_code=200,
        body=json.dumps(schema),
        forms=[],
        links=[],
        headers={"content-type": "application/json", "x-graphql-introspection": "true"},
    ))

    types_by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    root_types = {
        schema.get("queryType", {}).get("name", "Query"),
        schema.get("mutationType", {}).get("name", "Mutation"),
    }

    for type_name in root_types:
        root_type = types_by_name.get(type_name)
        if not root_type:
            continue
        for field in root_type.get("fields") or []:
            string_args = [
                a["name"] for a in (field.get("args") or [])
                if _is_string_type(a.get("type"))
            ]
            if not string_args:
                continue
            inputs = [{"name": a, "value": "test", "type": "text"} for a in string_args]
            pages.append(CrawlResult(
                url=endpoint,
                status_code=200,
                body="",
                forms=[{
                    "method": "post",
                    "action": endpoint,
                    "inputs": inputs,
                    "graphql_field": field["name"],
                }],
                links=[],
                headers={"content-type": "application/json"},
            ))

    return pages


def _fetch_introspection(endpoint: str, client: httpx.Client) -> Optional[dict]:
    try:
        resp = client.post(
            endpoint,
            json={"query": _INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        data = resp.json()
        return data.get("data", {}).get("__schema")
    except Exception:
        return None


def _is_string_type(type_obj: Optional[dict]) -> bool:
    if not type_obj:
        return False
    name = type_obj.get("name", "")
    if name in ("String", "ID"):
        return True
    of_type = type_obj.get("ofType")
    return _is_string_type(of_type) if of_type else False
