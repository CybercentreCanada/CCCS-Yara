"""Tests for the CTI (MITRE ATT&CK) knowledge base using mitreattack-python."""

import pytest

from cccs_yara.knowledge_bases.cti import CTIDatabase


@pytest.fixture(scope="module")
def cti():
    """Load CTI database once for all tests in this module."""
    return CTIDatabase()


# -- Lookup map tests --


def test_malware_lookup_populated(cti):
    assert len(cti.malware_lookup) > 0
    assert "Cobalt Strike" in cti.malware_lookup


def test_tool_lookup_populated(cti):
    assert len(cti.tool_lookup) > 0


def test_actor_lookup_populated(cti):
    assert len(cti.actor_lookup) > 0
    assert "APT28" in cti.actor_lookup


def test_malware_has_aliases(cti):
    aliases = cti.malware_lookup["Cobalt Strike"]
    assert "Cobalt Strike" in aliases


def test_actor_has_aliases(cti):
    aliases = cti.actor_lookup["APT28"]
    assert "Fancy Bear" in aliases


def test_malware_and_tool_are_disjoint(cti):
    """Malware and tool lookups should not share keys."""
    overlap = set(cti.malware_lookup) & set(cti.tool_lookup)
    assert not overlap, f"Unexpected overlap between malware and tool lookups: {overlap}"


# -- ID-based query tests --


def test_query_technique_by_id(cti):
    results = cti.query("T1059")
    assert len(results) >= 1
    assert results[0].name == "Command and Scripting Interpreter"


def test_query_software_by_id(cti):
    results = cti.query("S0154")
    assert len(results) >= 1
    assert results[0].name == "Cobalt Strike"


def test_query_group_by_id(cti):
    results = cti.query("G0007")
    assert len(results) >= 1
    assert results[0].name == "APT28"


def test_query_unknown_id_returns_empty(cti):
    assert cti.query("T9999") == []


# -- Name-based query tests --


def test_query_group_by_name_case_insensitive(cti):
    for name in ("APT28", "apt28", "Apt28"):
        results = cti.query(name, exhaustive_list=["intrusion-set"])
        assert len(results) >= 1, f"No results for {name!r}"
        assert results[0].name == "APT28"


def test_query_malware_by_name_case_insensitive(cti):
    for name in ("Cobalt Strike", "cobalt strike", "COBALT STRIKE"):
        results = cti.query(name, exhaustive_list=["malware"])
        assert len(results) >= 1, f"No results for {name!r}"
        assert results[0].name == "Cobalt Strike"


def test_query_name_no_match_returns_empty(cti):
    assert cti.query("NonExistentMalware12345", exhaustive_list=["malware"]) == []


def test_query_no_exhaustive_list_returns_empty(cti):
    """A plain name with no exhaustive_list and no ID prefix returns empty."""
    assert cti.query("APT28") == []


# -- Result attribute tests (used by enrichment.py) --


def test_query_result_has_description(cti):
    results = cti.query("S0154")
    assert hasattr(results[0], "description")
    assert len(results[0].description) > 0


def test_query_result_has_external_references(cti):
    results = cti.query("S0154")
    refs = results[0].external_references
    assert len(refs) > 0
    assert refs[0]["external_id"] == "S0154"
