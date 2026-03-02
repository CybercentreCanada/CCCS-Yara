import os
from datetime import datetime
from typing import List

import stix2.utils
from git import Repo
from stix2 import FileSystemSource, Filter

# add the casefold to the supported filter operations
from stix2.datastore.filters import FILTER_OPS

from cccs_yara.constants import WORKING_DIR

CTI_GIT_URL = os.environ.get("CTI_GIT_URL", "https://github.com/mitre/cti.git@ATT&CK-v18.1")

FILTER_OPS.append("casefold")


class FilterCasefold(Filter):
    def _check_property(self, stix_obj_property):
        """Check a property of a STIX Object against this casefold filter, but with a casefold operator.

        Args:
            stix_obj_property: value to check this filter against

        Returns:
            True if property matches the filter,
            False otherwise.
        """
        # Had to keep the following code so that
        # If filtering on a timestamp property and the filter value is a string,
        # try to convert the filter value to a datetime instance.
        if isinstance(stix_obj_property, datetime) and isinstance(self.value, str):
            filter_value = stix2.utils.parse_into_datetime(self.value)
        else:
            filter_value = self.value

        if self.op == "casefold":
            return stix_obj_property.casefold() == filter_value.casefold()
        else:
            Filter._check_property(self, stix_obj_property)


class CTIDatabase:
    """Class to handle CTI database operations."""

    def __init__(self):
        if "@" in CTI_GIT_URL:
            url, branch = CTI_GIT_URL.split("@")
        else:
            url, branch = CTI_GIT_URL, "main"
        clone_path = os.path.join(WORKING_DIR, "cti")
        if not os.path.exists(clone_path):
            # Clone the CTI repository if it doesn't exist
            Repo.clone_from(url, clone_path, branch=branch, depth=1)
        else:
            # Otherwise, you might want to pull the latest changes
            repo = Repo(clone_path)
            repo.git.checkout(branch)
            repo.remotes.origin.pull()

        # Initialize collections that are "attack" specific
        self.collections = [
            FileSystemSource(os.path.join(clone_path, source))
            for source in os.listdir(clone_path)
            if source.endswith("-attack")
        ]

        # Initialize lookup maps for quick access
        self.malware_lookup = {
            result["name"]: result.get("x_mitre_aliases", [])
            for result in self._query([Filter("type", "=", "malware")])
        }

        self.tool_lookup = {
            result["name"]: result.get("x_mitre_aliases", []) for result in self._query([Filter("type", "=", "tool")])
        }

        self.actor_lookup = {
            result["name"]: result.get("aliases", []) for result in self._query([Filter("type", "=", "intrusion-set")])
        }

    def _query(self, filters: List[Filter]) -> list:
        """Query all collections for a given indicator.

        Args:
            filters (List[Filter]): The filters to apply to the query.

        Returns:
            list: A list of STIX objects matching the filters.
        """
        results = []
        for collection in self.collections:
            r = collection.query(filters)
            if not r:
                continue
            results.extend(r)
        return results

    def query(self, indicator: str, exhaustive_list: list[str] = []) -> list:
        """Query the CTI database for a given indicator.

        Args:
            indicator (str): The indicator to query.
            exhaustive_list (list[str], optional): List of STIX object types to search if no ID match is found.

        Returns:
            list: A list of STIX objects matching the indicator.
        """
        if indicator.startswith("TA"):
            return self._query(
                [Filter("type", "=", "x-mitre-tactic"), Filter("external_references.external_id", "=", indicator)]
            )
        elif indicator.startswith("T"):
            return self._query(
                [Filter("type", "=", "attack-pattern"), Filter("external_references.external_id", "=", indicator)]
            )
        elif indicator.startswith("S"):
            return self._query(
                [Filter("type", "=", "malware"), Filter("external_references.external_id", "=", indicator)]
            ) + self._query([Filter("type", "=", "tool"), Filter("external_references.external_id", "=", indicator)])
        elif indicator.startswith("G"):
            return self._query(
                [Filter("type", "=", "intrusion-set"), Filter("external_references.external_id", "=", indicator)]
            )
        elif indicator.startswith("M"):
            return self._query(
                [Filter("type", "=", "course-of-action"), Filter("external_references.external_id", "=", indicator)]
            )
        elif exhaustive_list:
            # Hail mary for other types of indicators, typically when given a name and not an ID
            output = []
            for collection in exhaustive_list:
                output += self._query([Filter("type", "=", collection), FilterCasefold("name", "casefold", indicator)])
            return output
        return []
