import logging
import os

from git import Repo
from mitreattack.stix20 import MitreAttackData

from cccs_yara.constants import WORKING_DIR

logger = logging.getLogger(__name__)

CTI_GIT_URL = os.environ.get("CTI_GIT_URL", "https://github.com/mitre/cti.git@ATT&CK-v18.1")

# ATT&CK domains to load (each must have a <domain>.json bundle inside the cloned repo)
ATTACK_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")


class CTIDatabase:
    """Class to handle CTI database operations using mitreattack-python."""

    def __init__(self):
        if "@" in CTI_GIT_URL:
            url, branch = CTI_GIT_URL.split("@")
        else:
            url, branch = CTI_GIT_URL, "main"
        clone_path = os.path.join(WORKING_DIR, "cti")
        if not os.path.exists(clone_path):
            Repo.clone_from(url, clone_path, branch=branch, depth=1)
        else:
            repo = Repo(clone_path)
            repo.git.checkout(branch)
            repo.remotes.origin.pull()

        # Load each ATT&CK domain from its STIX bundle
        self._datasets: list[MitreAttackData] = []
        for domain in ATTACK_DOMAINS:
            bundle_path = os.path.join(clone_path, domain, f"{domain}.json")
            if os.path.exists(bundle_path):
                self._datasets.append(MitreAttackData(bundle_path))
            else:
                logger.warning("ATT&CK bundle not found: %s", bundle_path)

        # Build lookup maps (same structure as before for backwards compatibility)
        self.malware_lookup: dict[str, list[str]] = {}
        self.tool_lookup: dict[str, list[str]] = {}
        self.actor_lookup: dict[str, list[str]] = {}

        for ds in self._datasets:
            for sw in ds.get_software():
                aliases = getattr(sw, "x_mitre_aliases", []) or []
                if sw.type == "tool":
                    self.tool_lookup.setdefault(sw.name, []).extend(aliases)
                else:
                    self.malware_lookup.setdefault(sw.name, []).extend(aliases)

            for group in ds.get_groups():
                aliases = getattr(group, "aliases", []) or []
                self.actor_lookup.setdefault(group.name, []).extend(aliases)

    def query(self, indicator: str, exhaustive_list: None | list[str] = None) -> list:
        """Query the CTI database for a given indicator.

        Args:
            indicator: An ATT&CK ID (e.g. T1059, G0007, S0154) or a name to search for.
            exhaustive_list: STIX object types to search by name if no ID match is found
                             (e.g. ["intrusion-set", "malware"]).

        Returns:
            A list of STIX objects matching the indicator.
        """
        results = []

        # ID-based lookups
        prefix_to_types = {
            "TA": ["x-mitre-tactic"],
            "T": ["attack-pattern"],
            "S": ["malware", "tool"],
            "G": ["intrusion-set"],
            "M": ["course-of-action"],
        }

        # Find the matching prefix (check "TA" before "T")
        for prefix, matched_types in prefix_to_types.items():
            if indicator.startswith(prefix):
                for ds in self._datasets:
                    for stix_type in matched_types:
                        try:
                            obj = ds.get_object_by_attack_id(indicator, stix_type=stix_type)
                        except Exception:
                            logger.warning("Error querying CTI dataset for %s: %s", indicator, exc_info=True)
                            continue
                        if obj:
                            results.append(obj)
                return results

        # Name-based lookups (case-insensitive, since get_*_by_alias is case-sensitive)
        if exhaustive_list:
            indicator_lower = indicator.casefold()
            for stix_type in exhaustive_list:
                for ds in self._datasets:
                    if stix_type == "intrusion-set":
                        for obj in ds.get_groups():
                            aliases = getattr(obj, "aliases", []) or []
                            if obj.name.casefold() == indicator_lower or any(
                                a.casefold() == indicator_lower for a in aliases
                            ):
                                results.append(obj)
                    elif stix_type in ("malware", "tool"):
                        for obj in ds.get_software():
                            aliases = getattr(obj, "x_mitre_aliases", []) or []
                            if obj.name.casefold() == indicator_lower or any(
                                a.casefold() == indicator_lower for a in aliases
                            ):
                                results.append(obj)

        return results
