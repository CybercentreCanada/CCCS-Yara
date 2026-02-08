# The enrichment module for the YARA validator package
import re
from itertools import pairwise
from urllib.parse import urlparse

from cccs_yara.constants import ACTOR_TYPE_KEYWORDS, CATEGORY_KEYWORDS, GENERIC_HASH_REGEX, MALWARE_TYPE_KEYWORDS
from cccs_yara.knowledge_bases.cti import CTIDatabase
from cccs_yara.knowledge_bases.lazarusholic import ACTOR_NAMES as LAZARUSHOLIC_ACTOR_NAMES
from cccs_yara.knowledge_bases.malpedia import Malpedia
from cccs_yara.knowledge_bases.misp import MISP

# PaloAlto Unit 42 actor pattern format
# Ref: https://unit42.paloaltonetworks.com/unit-42-attribution-framework/
PALO_ALTO_UNIT42_ACTOR_PATTERN = r"CL-(UNK|STA|CRI|MIX)-\d{4}"

# Microsoft Threat Actor Groups pattern format
# Ref: https://www.microsoft.com/en-us/security/blog/microsoft-threat-actor-naming
MICROSOFT_THREAT_ACTOR_PATTERN = r"STORM-\d{4}|DEV-\d{4}"

# RecordedFuture's Insikt Threat Actor Groups pattern format
RECORDED_FUTURE_ACTOR_PATTERN = r"TAG-\d{2,3}"

# CERT-UA Threat Actor Groups pattern format
CERT_UA_ACTOR_PATTERN = r"UAC-?\d{4}"

# Mandiant's Uncategorized Threat Actor Groups pattern format
MANDIANT_ACTOR_PATTERN = r"UNC\d{3,4}"

# Proofpoint's Threat Actor Groups pattern format
PROOFPOINT_ACTOR_PATTERN = r"TA\d{3,4}"

# 360.net Threat Actor Groups pattern format
# Ref: https://apt.360.net/aptlist
APT360_ACTOR_PATTERN = r"APT-\w{1}-\d{1,2}"

# Generic threat actor pattern using an APT prefix
APT_ACTOR_PATTERN = r"APT\d{2,4}|APT-\d{2,4}"

THREAT_ACTOR_PATTERN = re.compile(
    f"""^{
        "|".join(
            [
                PALO_ALTO_UNIT42_ACTOR_PATTERN,
                MICROSOFT_THREAT_ACTOR_PATTERN,
                RECORDED_FUTURE_ACTOR_PATTERN,
                CERT_UA_ACTOR_PATTERN,
                MANDIANT_ACTOR_PATTERN,
                PROOFPOINT_ACTOR_PATTERN,
                APT360_ACTOR_PATTERN,
                APT_ACTOR_PATTERN,
            ]
        )
    }$"""
)


class Enricher:
    def __init__(self):
        self.malpedia = Malpedia()
        self.mitre = CTIDatabase()
        self.misp = MISP()

    def enrich_yara_rule(self, parsed_rule: dict) -> None:
        """Enrich a YARA rule's metadata based on validation errors.

        Args:
            parsed_rule (dict): Rule parsed by Plyara.
        """

        # Helper function to add metadata and optionally enrich further depending on the data
        def add_metadata(key: str, value: str):
            try:
                parsed_rule["metadata_kv"].setdefault(key, set()).add(value)
            except AttributeError:
                parsed_rule["metadata_kv"][key] = set([parsed_rule["metadata_kv"][key], value])

            # Further enrichment logic can be added here if needed
            if key == "actor":
                parsed_rule["metadata_kv"].setdefault("category", "MALWARE")
                if value.startswith("CL-"):
                    actor_type = value.split("-", 2)[1]
                    if actor_type == "STA":
                        # State-sponsored actor
                        parsed_rule["metadata_kv"].setdefault("actor_type", set()).add("APT")
                    elif actor_type == "CRI":
                        # Criminal actor
                        parsed_rule["metadata_kv"].setdefault("actor_type", set()).add("CRIMEWARE")
                    elif actor_type == "MIX":
                        # Mixed motives actor
                        parsed_rule["metadata_kv"].setdefault("actor_type", set()).add("APT")
                        parsed_rule["metadata_kv"].setdefault("actor_type", set()).add("CRIMEWARE")
                elif value.startswith("APT"):
                    parsed_rule["metadata_kv"].setdefault("actor_type", set()).add("APT")

                if "actor_type" not in parsed_rule["metadata_kv"]:
                    # Check if actor exists in Malpedia to get actor type
                    for actor_name, actor_aliases in self.malpedia.actor_lookup.items():
                        if value == actor_name or value in actor_aliases:
                            # Retrieve the description or type information from Malpedia
                            description = self.malpedia.actor_data.get(actor_name, {}).get("description", "")
                            for actor_type, keywords in ACTOR_TYPE_KEYWORDS.items():
                                if set(description.upper().split(" ")).intersection(set(keywords)):
                                    parsed_rule["metadata_kv"].setdefault("actor_type", set()).add(actor_type)

                # Check MITRE for actor type if not found in Malpedia
                if "actor_type" not in parsed_rule["metadata_kv"]:
                    results = self.mitre.query(value, exhaustive_list=["intrusion-set"])
                    for result in results:
                        description = result.get("description", "")
                        for actor_type, keywords in ACTOR_TYPE_KEYWORDS.items():
                            if set(description.upper().split(" ")).intersection(set(keywords)):
                                parsed_rule["metadata_kv"].setdefault("actor_type", set()).add(actor_type)

                        if result.get("external_references") and result["external_references"][0].get("external_id"):
                            parsed_rule["metadata_kv"].setdefault("mitre_att", set()).add(
                                result["external_references"][0]["external_id"]
                            )

            elif key == "malware":
                parsed_rule["metadata_kv"]["category"] = "MALWARE"
                if "malware_type" not in parsed_rule["metadata_kv"]:
                    # Check if malware exists in Malpedia to get malware type
                    for malware_name, malware_aliases in self.malpedia.malware_lookup.items():
                        if value == malware_name or value in malware_aliases:
                            # Retrieve the description or type information from Malpedia
                            description = self.malpedia.misp_data.get(malware_name, {}).get("description", "")
                            for malware_type, keywords in MALWARE_TYPE_KEYWORDS.items():
                                if set(description.upper().split(" ")).intersection(set(keywords)):
                                    parsed_rule["metadata_kv"].setdefault("malware_type", set()).add(malware_type)

                # Check MITRE for malware type if not found in Malpedia
                if "malware_type" not in parsed_rule["metadata_kv"]:
                    results = self.mitre.query(value, exhaustive_list=["malware"])
                    for result in results:
                        description = result.get("description", "")
                        for malware_type, keywords in MALWARE_TYPE_KEYWORDS.items():
                            if set(description.upper().split(" ")).intersection(set(keywords)):
                                parsed_rule["metadata_kv"].setdefault("malware_type", set()).add(malware_type)
                        if result.get("external_references") and result["external_references"][0].get("external_id"):
                            parsed_rule["metadata_kv"].setdefault("mitre_att", set()).add(
                                result["external_references"][0]["external_id"]
                            )

            elif key == "malware_type":
                # If malware type has been determined, set category to MALWARE
                parsed_rule["metadata_kv"]["category"] = "MALWARE"

        # Build up candidate terms from rule name, tags, and metadata
        candidate_terms = set()
        hash_terms = set()
        rule_name = parsed_rule.get("rule_name", "")
        if "_" in rule_name:
            for curr, next in pairwise(parsed_rule.get("rule_name", "").upper().split("_")):
                candidate_terms.add(curr)
                candidate_terms.add(next)
                # Consider two-word combinations in the rule name as well
                candidate_terms.add(f"{curr}{next}")
        else:
            candidate_terms.add(rule_name.upper())

        # Include tags as candidate terms
        candidate_terms.update([tag.upper() for tag in parsed_rule.get("tags", [])])

        # Include metadata values as candidate terms
        for meta_key, meta_value in list(parsed_rule["metadata_kv"].items()) + [
            ("filename", parsed_rule.get("filename", "")),
        ]:
            if meta_key in ["fingerprint", "id", "version"]:
                continue
            if isinstance(meta_value, str):
                if re.match(GENERIC_HASH_REGEX, meta_value):
                    hash_terms.add(meta_value)
                    continue
                c_terms = []
                meta_value = meta_value.replace("(", "").replace(")", "")
                if meta_value.startswith("http"):
                    # Parse the URL to extract meaningful terms
                    parsed_url = urlparse(meta_value)
                    if meta_value.endswith("/"):
                        c_terms = parsed_url.path[:-1].split("/")[-1].split("-")
                    else:
                        c_terms = parsed_url.path.split("/")[-1].split("-")

                    if len(c_terms) == 1:
                        c_terms = c_terms[0].split("_")
                else:
                    c_terms = meta_value.replace("/", " ").split(" ")

                for term, next in pairwise(c_terms):
                    candidate_terms.add(term)
                    candidate_terms.add(next)
                    # Consider two-word combinations as well
                    candidate_terms.add(f"{term}{next}")
            elif isinstance(meta_value, list):
                for item in meta_value:
                    if re.match(GENERIC_HASH_REGEX, item):
                        hash_terms.add(item)
                        continue
                    c_terms = []
                    if item.startswith("http"):
                        # Parse the URL to extract meaningful terms
                        parsed_url = urlparse(item)
                        if item.endswith("/"):
                            c_terms = parsed_url.path[:-1].split("/")[-1].split("-")
                        else:
                            c_terms = parsed_url.path.split("/")[-1].split("-")

                        if len(c_terms) == 1:
                            c_terms = c_terms[0].split("_")
                    else:
                        c_terms = item.replace("/", " ").split(" ")

                    for term, next in pairwise(c_terms):
                        candidate_terms.add(term)
                        candidate_terms.add(next)
                        # Consider two-word combinations as well
                        candidate_terms.add(f"{term}{next}")

        # Filter out terms that aren't useful
        candidate_terms = [
            # Filter out empty terms, numeric terms, and generic hashes, and sharing markings
            # to reduce the search space when querying knowledge bases
            term.upper()
            for term in candidate_terms
            if term and not GENERIC_HASH_REGEX.match(term) and not term.upper().startswith("TLP:")
        ]

        for term in candidate_terms:
            match_found = THREAT_ACTOR_PATTERN.match(term)
            if match_found:
                actor_name = match_found.group(0)
                add_metadata("actor", actor_name)
                break

        # Check if we can determine the malware type based on the description
        for malware_type, keywords in MALWARE_TYPE_KEYWORDS.items():
            if set(candidate_terms).intersection(set(keywords)):
                add_metadata("malware_type", malware_type)

        for actor_type, keywords in ACTOR_TYPE_KEYWORDS.items():
            if set(candidate_terms).intersection(set(keywords)):
                add_metadata("actor_type", actor_type)

        # Rely on knowledge bases to enrich the rule metadata
        for malware_family, malware_synonyms in list(self.malpedia.malware_lookup.items()) + list(
            self.mitre.malware_lookup.items()
        ):
            if set(malware_synonyms + [malware_family]).intersection(set(candidate_terms)):
                add_metadata("malware", malware_family.upper())
                break

        for actor_name, actor_synonyms in list(self.malpedia.actor_lookup.items()) + list(
            self.mitre.actor_lookup.items()
        ):
            if set(actor_synonyms + [actor_name]).intersection(set(candidate_terms)):
                add_metadata("actor", actor_name.upper())
                break

        if not any(key in parsed_rule["metadata_kv"] for key in ["malware", "actor"]):
            for term in candidate_terms:
                for cluster, cluster_values in self.misp.search(term):
                    if cluster.category == "actor":
                        for value in cluster_values:
                            add_metadata("actor", value.value)
                    elif cluster.category == "tool":
                        malware_type = None
                        if cluster.type == "botnet":
                            malware_type = "BOT"
                        elif cluster.type.upper() in MALWARE_TYPE_KEYWORDS:
                            malware_type = cluster.type.upper()

                        if not malware_type:
                            continue

                        for value in cluster_values:
                            add_metadata("malware", value.value)
                            add_metadata("malware_type", malware_type)

        for actor_name in LAZARUSHOLIC_ACTOR_NAMES:
            if actor_name in candidate_terms:
                add_metadata("actor", actor_name)
                break

        if "category" not in parsed_rule["metadata_kv"]:
            if "malware_type" in parsed_rule["metadata_kv"]:
                # Ensure category is set to MALWARE if malware_type is present
                parsed_rule["metadata_kv"]["category"] = "MALWARE"
            else:
                for category, keywords in CATEGORY_KEYWORDS.items():
                    if set(keywords).intersection(set(candidate_terms)):
                        # Assign category based on keywords found in the rule metadata
                        parsed_rule["metadata_kv"]["category"] = category
                        break

        # Handle misattribution of malware and actor metadata by checking for conflicting terms
        if "COBALT" in parsed_rule["metadata_kv"].get("actor", []) and "COBALT STRIKE" in parsed_rule[
            "metadata_kv"
        ].get("malware", []):
            # Cobalt actor was likely misattributed because of similarity to Cobalt Strike malware,
            # remove actor metadata
            parsed_rule["metadata_kv"]["actor"].remove("COBALT")

        # Cleanup metadata that has no value after enrichment
        for key in list(parsed_rule["metadata_kv"].keys()):
            if not parsed_rule["metadata_kv"][key]:
                del parsed_rule["metadata_kv"][key]
