import pytest
from plyara import Plyara


# https://github.com/CybercentreCanada/CCCS-Yara/issues/61
def test_metadata_parsing():
    # Bug: Metadata parsing would fail on different formats of yara rules
    RULES = """
rule testing
{ meta:
    key = "value"
  condition:
    true
}

rule testing {
  meta:
    key = "value"
  strings: $re = /test/
  condition: $re
}

rule testing
{ meta:
    key = "value"
  condition: true
}

rule testing { meta: key = "value" condition: true }
"""

    p = Plyara(meta_as_kv=True)
    parsed_rules = p.parse_string(RULES)

    # We expect 4 rules to be parsed successfully
    assert len(parsed_rules) == 4

    # Of these 4 rules, each should have metadata with the key "key" and value "value"
    for rule in parsed_rules:
        assert "metadata_kv" in rule
        assert rule["metadata_kv"].get("key") == "value"
