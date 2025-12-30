import json
import os
from typing import List, Union

from git import Repo
from pymispgalaxies import Cluster, Clusters, ClusterValue

from cccs_yara.constants import WORKING_DIR

MISP_GALAXIES_GIT_URL = os.environ.get("MISP_GALAXIES_GIT_URL", "https://github.com/MISP/misp-galaxy.git")


# Change search method to allow for case insensitive search and ignore partial string matches
def search_override(self, query: str, return_tags: bool = False) -> Union[List[ClusterValue], List[str]]:
    """Searches for values in the cluster that match the given query.

    Args:
        self (Cluster): The cluster to search in.
        query (str): The query to search for.
        return_tags (bool, optional): Flag indicating whether to return machine tags instead of cluster values.
        Defaults to False.

    Returns:
        Union[List[ClusterValue], List[str]]: A list of matching cluster values or machine tags.
    """
    matching = []
    for v in self.values():
        if query.upper() in [s.upper() for s in v.searchable]:
            if return_tags:
                matching.append('misp-galaxy:{}="{}"'.format(self.type, v.value))
            else:
                matching.append(v)
    return matching


setattr(Cluster, "search", search_override)  # type: ignore


class MISP:
    def __init__(
        self,
        clusters: List[str] = [
            "backdoor",
            "banker",
            "botnet",
            "cryptominers",
            "microsoft-activity-group",
            "rat",
            "stealer",
            "threat-actor",
            "tidal-groups",
            "tidal-software",
            "tool",
        ],
    ):
        # Initialize MISP clusters
        clone_path = os.path.join(WORKING_DIR, "misp-galaxy")
        if not os.path.exists(clone_path):
            # Clone the CTI repository if it doesn't exist
            Repo.clone_from(MISP_GALAXIES_GIT_URL, clone_path, depth=1)
        else:
            # Otherwise, you might want to pull the latest changes
            repo = Repo(clone_path)
            repo.remotes.origin.pull()

        clusters_data = []
        # Clone the misp-galaxies repository if not already present
        for cluster in clusters:
            cluster_path = os.path.join(clone_path, "clusters", f"{cluster}.json")
            with open(cluster_path, "r") as f:
                data = json.load(f)

            # Add synonyms to each cluster value to make search more effective
            for value in data.get("values", []):
                value["synonyms"] = value.get("meta", {}).get("synonyms", []) + [value["value"]]

            clusters_data.append(data)

        self.clusters = Clusters(clusters_data)

    def search(self, query: str) -> Union[List[ClusterValue], List[str]]:
        return self.clusters.search(query)
