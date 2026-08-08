#!/usr/bin/env python3
import hashlib
import json
import math
import pathlib
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "fixtures/protocol/cross-language-vectors.v1.json"

RESOURCE_CONTEXT_SCHEMA = "toolkit.entitlement.resource-context.v1"
RESOURCE_CONTEXT_EMPTY_SCHEMA = f"{RESOURCE_CONTEXT_SCHEMA}.empty"
MUTATION_REQUEST_SCHEMA = "toolkit.mutation-request.v1"

RESOURCE_CONTEXT_FIELDS = {
    "schemaVersion": {"type": "enum", "values": [RESOURCE_CONTEXT_SCHEMA]},
    "action": {"type": "string", "required": True, "nonEmpty": True},
    "resourceType": {"type": "string", "required": True, "nonEmpty": True},
    "resourceId": {"type": "string"},
    "resourceVersion": {"type": "integer"},
    "ownerType": {"type": "enum", "required": True, "values": ["user", "workspace"]},
    "ownerId": {"type": "string", "required": True, "nonEmpty": True},
    "workspaceId": {"type": "string"},
    "contextSchema": {"type": "string"},
    "context": {"type": "jsonObject"},
}

PAYLOAD_SCHEMAS = {
    "toolkit.digest-vector.v1": {
        "label": {"type": "string", "required": True},
        "optional": {"type": "string", "nullable": True},
        "ordered": {"type": "array", "items": {"type": "string"}},
        "tags": {"type": "set", "items": {"type": "string"}},
        "count": {"type": "integer"},
    }
}


def is_plain_object(value):
    return isinstance(value, dict)


def canonical(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            raise ValueError("safe integer")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("finite")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise ValueError("negative-zero")
        if not value.is_integer() or abs(value) > 9007199254740991:
            raise ValueError("safe integer")
        return int(value)
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    raise ValueError("unsupported canonical JSON value")


def canonical_json(value):
    return json.dumps(canonical(value), ensure_ascii=False, separators=(",", ":"))


def sha256_digest(value):
    body = canonical_json(value)
    return f"sha256:{hashlib.sha256(body.encode('utf-8')).hexdigest()}"


def normalize_schema_value(value, spec, path):
    if value is _MISSING:
        if spec.get("required"):
            raise ValueError(f"{path} is required")
        return _MISSING
    if value is None:
        if spec.get("nullable"):
            return None
        raise ValueError(f"{path} must not be null")
    value_type = spec.get("type")
    if value_type == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string")
        normalized = unicodedata.normalize("NFC", value)
        if spec.get("nonEmpty") and not normalized:
            raise ValueError(f"{path} must not be empty")
        return normalized
    if value_type == "enum":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string enum")
        normalized = unicodedata.normalize("NFC", value)
        if normalized not in spec["values"]:
            raise ValueError(f"{path} is not allowed")
        return normalized
    if value_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool) or abs(value) > 9007199254740991:
            raise ValueError(f"{path} must be a safe integer")
        return value
    if value_type == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array")
        return [normalize_schema_value(item, spec.get("items", {"type": "json"}), f"{path}[{idx}]") for idx, item in enumerate(value)]
    if value_type == "set":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a set array")
        items = [normalize_schema_value(item, spec.get("items", {"type": "json"}), f"{path}[{idx}]") for idx, item in enumerate(value)]
        keyed = [(canonical_json(item), item) for item in items]
        keys = [key for key, _ in keyed]
        if len(set(keys)) != len(keys):
            raise ValueError(f"{path} must not contain duplicate set items")
        return [item for _, item in sorted(keyed)]
    if value_type == "jsonObject":
        if not is_plain_object(value):
            raise ValueError(f"{path} must be an object")
        return canonical(value)
    if value_type == "json":
        return canonical(value)
    raise ValueError(f"{path} has unsupported schema type")


_MISSING = object()


def normalize_object_by_fields(value, fields, path):
    if not is_plain_object(value):
        raise ValueError(f"{path} must be an object")
    allowed = set(fields)
    for key in value:
        if key not in allowed:
            raise ValueError(f"{path}.{key} is not allowed")
    normalized = {}
    for key in sorted(fields):
        raw = value[key] if key in value else _MISSING
        item = normalize_schema_value(raw, fields[key], f"{path}.{key}")
        if item is not _MISSING:
            normalized[key] = item
    return normalized


def normalize_resource_context(resource_context, action=""):
    raw = dict(resource_context or {})
    raw["action"] = str(action or raw.get("action", ""))
    raw["ownerType"] = str(raw.get("ownerType") or "user")
    ctx = normalize_object_by_fields(raw, RESOURCE_CONTEXT_FIELDS, "resourceContext")
    if not ctx.get("action") or not ctx.get("resourceType") or not ctx.get("ownerId"):
        raise ValueError("resource context is incomplete")
    if ctx.get("contextSchema") and ctx["contextSchema"] != RESOURCE_CONTEXT_EMPTY_SCHEMA:
        raise ValueError("unknown resource context schema")
    if ctx.get("contextSchema") and "context" not in ctx:
        ctx["context"] = {}
    return {"schemaVersion": RESOURCE_CONTEXT_SCHEMA, **ctx}


def resource_context_digest(action, resource_context):
    return sha256_digest(normalize_resource_context(resource_context, action))


def normalize_payload(payload_schema, payload):
    if payload_schema not in PAYLOAD_SCHEMAS:
        raise ValueError(f"unknown mutation payload schema: {payload_schema}")
    return normalize_object_by_fields(payload or {}, PAYLOAD_SCHEMAS[payload_schema], "payload")


def mutation_request_body(input_value):
    features = sorted(str(item) for item in input_value.get("features", []))
    if len(set(features)) != len(input_value.get("features", [])):
        raise ValueError("features must not contain duplicates")
    payload_schema = str(input_value.get("payloadSchema", ""))
    action = str(input_value.get("action", ""))
    return {
        "schemaVersion": MUTATION_REQUEST_SCHEMA,
        "action": action,
        "resourceContextDigest": resource_context_digest(action, input_value.get("resourceContext", {})),
        "authorizationRulesDigest": str(input_value.get("authorizationRulesDigest", "")),
        "features": features,
        "payloadSchema": payload_schema,
        "payload": normalize_payload(payload_schema, input_value.get("payload", {})),
    }


def mutation_request_digest(input_value):
    return sha256_digest(mutation_request_body(input_value))


def verify_positive_vector(vector):
    kind = vector["kind"]
    if kind == "canonical-json":
        body = canonical_json(vector["input"])
        digest = sha256_digest(vector["input"])
    elif kind == "resource-context-digest":
        body = canonical_json(normalize_resource_context(vector["input"], vector["input"].get("action", "")))
        digest = resource_context_digest(vector["input"].get("action", ""), vector["input"])
    elif kind == "mutation-request-digest":
        body = canonical_json(mutation_request_body(vector["input"]))
        digest = mutation_request_digest(vector["input"])
    else:
        raise AssertionError(f"unknown vector kind: {kind}")
    assert body == vector["expectedBody"], f"{vector['name']} body mismatch"
    assert digest == vector["expectedDigest"], f"{vector['name']} digest mismatch"


def verify_negative_vector(vector):
    try:
        if vector["kind"] == "canonical-json":
            shape = vector.get("valueShape", {})
            if shape.get("field") == "undefined":
                raise ValueError("undefined")
            if shape.get("n") == "NaN":
                canonical_json({"n": float("nan")})
            elif shape.get("n") == "-0":
                canonical_json({"n": -0.0})
            else:
                canonical_json(vector.get("input", {}))
        elif vector["kind"] == "resource-context-digest":
            resource_context_digest(vector["input"].get("action", ""), vector["input"])
        elif vector["kind"] == "mutation-request-digest":
            mutation_request_digest(vector["input"])
        else:
            raise AssertionError(f"unknown negative kind: {vector['kind']}")
    except Exception as exc:
        assert vector["expectedError"] in str(exc), f"{vector['name']} expected {vector['expectedError']}, got {exc}"
        return
    raise AssertionError(f"{vector['name']} did not fail")


def main():
    pack = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert pack["schemaVersion"] == "toolkit.protocol.cross-language-vectors.v1"
    for vector in pack["vectors"]:
        verify_positive_vector(vector)
    for vector in pack["negativeVectors"]:
        verify_negative_vector(vector)
    print("protocol cross-language python self-test ok")


if __name__ == "__main__":
    main()
