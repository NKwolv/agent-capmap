import hashlib

from agentcapmap.enumerate.hashing import (
    canonical_tool_definition,
    server_definition_hash,
    tool_definition_hash,
)


def test_canonical_form_is_key_order_independent() -> None:
    a = {"type": "object", "properties": {"b": {"type": "string"}, "a": {"type": "integer"}}}
    b = {"properties": {"a": {"type": "integer"}, "b": {"type": "string"}}, "type": "object"}
    assert tool_definition_hash("t", "d", a) == tool_definition_hash("t", "d", b)


def test_canonical_bytes_known_vector() -> None:
    data = canonical_tool_definition("echo", "Echo text", {"type": "object"})
    assert data == b'{"description":"Echo text","inputSchema":{"type":"object"},"name":"echo"}'
    assert tool_definition_hash("echo", "Echo text", {"type": "object"}) == (
        hashlib.sha256(data).hexdigest()
    )


def test_any_field_change_changes_hash() -> None:
    base = tool_definition_hash("t", "d", {"type": "object"})
    assert tool_definition_hash("t2", "d", {"type": "object"}) != base
    assert tool_definition_hash("t", "d ", {"type": "object"}) != base
    assert tool_definition_hash("t", "d", {"type": "array"}) != base


def test_missing_fields_normalize() -> None:
    assert tool_definition_hash("t", None, None) == tool_definition_hash("t", "", {})


def test_unicode_is_hashed_as_utf8() -> None:
    # Hidden-instruction payloads often use non-ASCII; they must affect the hash.
    zero_width_space = chr(0x200B)
    assert tool_definition_hash("t", f"read{zero_width_space}file", {}) != (
        tool_definition_hash("t", "readfile", {})
    )


def test_server_hash_is_order_independent() -> None:
    assert server_definition_hash(["a", "b"]) == server_definition_hash(["b", "a"])
    assert server_definition_hash(["a"]) != server_definition_hash(["a", "b"])
