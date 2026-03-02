from cccs_yara.enrichment import Enricher


def test_general_enrichment():
    # Reference: https://github.com/SEKOIA-IO/Community/blob/main/yara_rules/apt_agent_racoon_strings.yar
    parsed_rule = {
        "rule_name": "apt_agent_racoon",
        "metadata_kv": {
            "description": "Detects Agent Racoon used by CL-STA-0002",
        },
    }

    # Based on the description of the rule and the rule name,
    # we should be able to enrich it with the actor and malware family
    enricher = Enricher()
    enricher.enrich_yara_rule(parsed_rule)

    assert parsed_rule["metadata_kv"] == {
        "description": "Detects Agent Racoon used by CL-STA-0002",
        "actor": {"CL-STA-0002"},
        "category": "MALWARE",
        "actor_type": {"APT"},
        "malware_type": {"APT"},
        "malware": {"AGENT RACOON"},
    }
