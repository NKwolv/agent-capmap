import pytest

from agentcapmap.discovery._common import ConfigError, find_key_line, load_jsonc


def test_comments_and_trailing_commas() -> None:
    text = """{
      // line comment
      "a": "http://not-a-comment", /* block
      comment */ "b": [1, 2,],
      "c": "has /* fake */ comment",
    }"""
    assert load_jsonc(text) == {
        "a": "http://not-a-comment",
        "b": [1, 2],
        "c": "has /* fake */ comment",
    }


def test_escaped_quotes_in_strings() -> None:
    assert load_jsonc(r'{"a": "say \"hi\" // ok"}') == {"a": 'say "hi" // ok'}


def test_invalid_json_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_jsonc('{"a": }')
    with pytest.raises(ConfigError, match="unterminated"):
        load_jsonc('{"a": 1 /* oops')


def test_find_key_line() -> None:
    text = '{\n  "servers": {\n    "github": {}\n  }\n}'
    assert find_key_line(text, "github") == 3
    assert find_key_line(text, "missing") is None
