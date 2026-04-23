import json
import logging
import os

import requests

from cccs_yara.constants import WORKING_DIR

logger = logging.getLogger(__name__)

MALPEDIA_MISP_URL = os.environ.get(
    "MALPEDIA_MISP_URL",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/misp",
)

MALPEDIA_ACTORS_URL = os.environ.get(
    "MALPEDIA_ACTORS_URL",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors",
)


def _fetch_or_load(cache_path: str, url: str) -> dict:
    """Load JSON from a local cache file, or fetch from a URL and cache the result.

    Args:
        cache_path: Path to the local cache file.
        url: Remote URL to fetch if the cache does not exist.

    Returns:
        Parsed JSON data, or an empty dict on failure.
    """
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)

    response = requests.get(url, timeout=5)
    response.raise_for_status()
    data = response.json()
    with open(cache_path, "w") as f:
        json.dump(data, f)
    return data


class Malpedia:
    def __init__(self, misp_url: str = MALPEDIA_MISP_URL, actors_url: str = MALPEDIA_ACTORS_URL):
        # Initialize malware lookup dictionary
        self.malware_lookup = {}
        self.misp_data = {}
        try:
            misp_data = _fetch_or_load(os.path.join(WORKING_DIR, "malpedia_misp.json"), misp_url)

            for record in misp_data.get("values", []):
                # Strip out any thing OS-related from the malware family names
                for operating_system in ["Windows", "Linux", "OS X", "Android"]:
                    record["value"] = record["value"].replace(f" ({operating_system})", "")
                self.malware_lookup[record["value"]] = []
                for synonym in record["meta"].get("synonyms", []) + [record["value"]]:
                    # Add synonym in uppercase
                    self.malware_lookup[record["value"]].append(synonym.upper())
                    if " " in synonym:
                        # Also add synonym without spaces
                        self.malware_lookup[record["value"]].append(synonym.replace(" ", "").upper())

                self.misp_data[record["value"]] = record["meta"]
        except (requests.RequestException, json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning("Failed to load Malpedia malware data: %s", e)

        # Initialize actor lookup dictionary
        self.actor_lookup = {}
        self.actor_data = {}
        try:
            self.actor_data = _fetch_or_load(os.path.join(WORKING_DIR, "malpedia_actors.json"), actors_url)

            for record in self.actor_data.values():
                self.actor_lookup[record["value"]] = [
                    record["value"].upper().replace("OPERATION ", "").replace(" ", "")
                ]
                for synonym in record.get("meta", {}).get("synonyms", []) + [record["value"]]:
                    # Add synonym in uppercase
                    self.actor_lookup[record["value"]].append(synonym.upper())
                    if " " in synonym:
                        # Also add synonym without spaces
                        self.actor_lookup[record["value"]].append(synonym.replace(" ", "").upper())
        except (requests.RequestException, json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning("Failed to load Malpedia actor data: %s", e)
