import json
import logging
import os
from typing import List, Tuple, Union

from git import Repo
from pymispgalaxies import Cluster, Clusters, ClusterValue

from cccs_yara.constants import WORKING_DIR

logger = logging.getLogger(__name__)

MISP_GALAXIES_GIT_URL = os.environ.get("MISP_GALAXIES_GIT_URL", "https://github.com/MISP/misp-galaxy.git")


def _search_cluster(cluster: Cluster, query: str) -> List[ClusterValue]:
    """Case-insensitive exact search across cluster values without monkey-patching."""
    query_upper = query.upper()
    return [v for v in cluster.values() if query_upper in [s.upper() for s in v.searchable]]


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
            Repo.clone_from(MISP_GALAXIES_GIT_URL, clone_path, depth=1)
        else:
            repo = Repo(clone_path)
            repo.remotes.origin.pull()

        clusters_data = []
        for cluster in clusters:
            cluster_path = os.path.join(clone_path, "clusters", f"{cluster}.json")
            with open(cluster_path, "r") as f:
                data = json.load(f)

            # Add synonyms to each cluster value to make search more effective
            for value in data.get("values", []):
                value["synonyms"] = value.get("meta", {}).get("synonyms", []) + [value["value"]]

            clusters_data.append(data)

        self.clusters = Clusters(clusters_data)

    def search(self, query: str) -> List[Tuple[Cluster, List[ClusterValue]]]:
        """Search all loaded clusters for the given query (case-insensitive, exact match)."""
        results = []
        for cluster in self.clusters.values():
            matches = _search_cluster(cluster, query)
            if matches:
                results.append((cluster, matches))
        return results
