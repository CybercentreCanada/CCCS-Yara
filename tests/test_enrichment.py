import pytest

from cccs_yara.enrichment import Enricher


@pytest.fixture(scope="module")
def enricher():
    """Instantiate the Enricher module once for all tests in this module."""
    return Enricher()


def test_general_enrichment(enricher):
    # Reference: https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/apt_agent_racoon_strings.yar
    parsed_rule = {
        "rule_name": "apt_agent_racoon",
        "metadata_kv": {
            "description": "Detects Agent Racoon used by CL-STA-0002",
        },
    }

    # Based on the description of the rule and the rule name,
    # we should be able to enrich it with the actor and malware family
    enricher.enrich_yara_rule(parsed_rule)

    assert parsed_rule["metadata_kv"] == {
        "description": "Detects Agent Racoon used by CL-STA-0002",
        "actor": {"CL-STA-0002"},
        "category": "MALWARE",
        "actor_type": {"APT"},
        "malware_type": {"APT"},
        "malware": {"AGENT RACOON"},
    }


def test_single_token_enrichment(enricher):
    # A rule whose name has no underscores (single token) and whose metadata
    # contains only one-word values should still be enriched correctly.

    # Single-token rule name that matches a known actor pattern
    parsed_rule = {
        "rule_name": "CL-STA-0002",
        "metadata_kv": {},
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "actor" in parsed_rule["metadata_kv"], "Actor should be enriched from a single-token rule name"
    assert "CL-STA-0002" in parsed_rule["metadata_kv"]["actor"]

    # Single-word description value (one token, no spaces — pairwise previously dropped this)
    parsed_rule2 = {
        "rule_name": "detect_lazarus",
        "metadata_kv": {
            "description": "LAZARUS",
        },
    }
    enricher.enrich_yara_rule(parsed_rule2)
    assert "actor" in parsed_rule2["metadata_kv"], "Actor should be enriched from a single-word description"


@pytest.mark.parametrize("description", ["Cobaltstrike", "Cobalt Strike"])
def test_cobalt_strike_description_enrichment(enricher, description):
    parsed_rule = {
        "rule_name": "detect_tooling",
        "metadata_kv": {
            "description": description,
        },
    }

    enricher.enrich_yara_rule(parsed_rule)

    assert parsed_rule["metadata_kv"].get("malware") == {"COBALT STRIKE"}
    assert "COBALT" not in parsed_rule["metadata_kv"].get("actor", set())


@pytest.mark.parametrize("rule_name", ["cobaltstrike_payload", "cobalt_strike_payload"])
def test_cobalt_strike_rule_name_enrichment(enricher, rule_name):
    parsed_rule = {
        "rule_name": rule_name,
        "metadata_kv": {
            "description": "detects suspicious payload",
        },
    }

    enricher.enrich_yara_rule(parsed_rule)

    assert parsed_rule["metadata_kv"].get("malware") == {"COBALT STRIKE"}
    assert "COBALT" not in parsed_rule["metadata_kv"].get("actor", set())


@pytest.mark.parametrize("description", ["do not", "please do not"])
def test_do_not_does_not_match_donot_malware(enricher, description):
    parsed_rule = {
        "rule_name": "test_rule",
        "metadata_kv": {
            "description": description,
        },
    }

    enricher.enrich_yara_rule(parsed_rule)

    assert "malware" not in parsed_rule["metadata_kv"]


@pytest.mark.parametrize("description", ["donot", "please donot"])
def test_donot_matches_donot_malware(enricher, description):
    parsed_rule = {
        "rule_name": "test_rule",
        "metadata_kv": {
            "description": description,
        },
    }

    enricher.enrich_yara_rule(parsed_rule)

    assert parsed_rule["metadata_kv"].get("malware") == {"DONOT"}
