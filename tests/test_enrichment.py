import pytest

from cccs_yara.enrichment import THREAT_ACTOR_PATTERN, Enricher


@pytest.fixture(scope="module")
def enricher():
    """Instantiate the Enricher module once for all tests in this module.

    Returns:
        Enricher: An instance of the Enricher class to be used in tests.
    """
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


@pytest.mark.parametrize(
    "actor_id,match_found",
    [
        ("CL-STA-0002", True),
        ("CL-CRI-0001", True),
        ("CL-UNK-0003", True),
        ("CL-MIX-0010", True),
        ("STORM-1234", True),
        ("DEV-0001", True),
        ("TAG-99", True),
        ("TAG-100", True),
        ("UAC-0001", True),
        ("UAC0001", True),
        ("UNC1234", True),
        ("UNC123", True),
        ("TA453", True),
        ("TA4534", True),
        ("APT-A-1", True),
        ("APT28", True),
        ("APT-28", True),
        ("NOTAPATTERN", False),
        ("CL-BAD-0001", False),
        ("STORM", False),
        ("T1059", False),
        ("randomstring", False),
        ("", False),
    ],
)
def test_actor_patterns(actor_id, match_found):
    assert bool(THREAT_ACTOR_PATTERN.match(actor_id)) == match_found, (
        f"Expected {actor_id} to be {'valid' if match_found else 'invalid'}"
    )


def test_category_inferred_from_filename(enricher):
    parsed_rule = {
        "rule_name": "some_detection",
        "metadata_kv": {},
        "filename": "apt_some_detection.yar",
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert parsed_rule["metadata_kv"].get("category") == "MALWARE"


def test_malware_type_keywords_enrichment(enricher):
    parsed_rule = {
        "rule_name": "ransomware_locker",
        "metadata_kv": {
            "description": "Detects ransomware activity",
        },
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "RANSOMWARE" in parsed_rule["metadata_kv"].get("malware_type", set())


def test_actor_type_keywords_enrichment(enricher):
    parsed_rule = {
        "rule_name": "apt_detector",
        "metadata_kv": {
            "description": "Detects APT activity",
        },
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "APT" in parsed_rule["metadata_kv"].get("actor_type", set())


def test_threat_actor_pattern_enrichment(enricher):
    parsed_rule = {
        "rule_name": "CL_STA_0002_loader",
        "metadata_kv": {
            "description": "Detects CL-STA-0002 implant",
        },
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "CL-STA-0002" in parsed_rule["metadata_kv"].get("actor", set())


def test_url_metadata_term_extraction(enricher):
    """URLs in metadata should be parsed for meaningful terms."""
    parsed_rule = {
        "rule_name": "test_rule",
        "metadata_kv": {
            "reference": "https://example.com/analysis/emotet-loader",
            "description": "Test rule",
        },
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "EMOTET" in parsed_rule["metadata_kv"].get("malware", set()) or "category" in parsed_rule["metadata_kv"]


def test_cobalt_misattribution_fix(enricher):
    """When Cobalt Strike is detected as malware, Cobalt actor should be removed."""
    parsed_rule = {
        "rule_name": "cobalt_strike_beacon",
        "metadata_kv": {
            "description": "Detects Cobalt Strike beacon",
        },
    }
    enricher.enrich_yara_rule(parsed_rule)
    assert "COBALT STRIKE" in parsed_rule["metadata_kv"].get("malware", set())
    assert "COBALT" not in parsed_rule["metadata_kv"].get("actor", set())
