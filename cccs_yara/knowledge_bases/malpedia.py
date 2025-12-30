import json
import os

import requests

from cccs_yara.constants import WORKING_DIR

MALPEDIA_MISP_URL = os.environ.get(
    "MALPEDIA_MISP_URL",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/misp",
)

MALPEDIA_ACTORS_URL = os.environ.get(
    "MALPEDIA_ACTORS_URL",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors",
)


class Malpedia:
    def __init__(self, misp_url: str = MALPEDIA_MISP_URL, actors_url: str = MALPEDIA_ACTORS_URL):
        # Initialize malware lookup dictionary
        try:
            self.malware_lookup = {}
            self.misp_data = {}
            if os.path.exists(os.path.join(WORKING_DIR, "malpedia_misp.json")):
                with open(os.path.join(WORKING_DIR, "malpedia_misp.json")) as f:
                    misp_data = json.load(f)
            else:
                misp_data = requests.get(misp_url, timeout=5).json()
                with open(os.path.join(WORKING_DIR, "malpedia_misp.json"), "w") as f:
                    json.dump(misp_data, f)

            for record in misp_data["values"]:
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
        except requests.ConnectTimeout:
            pass

        # Initialize actor lookup dictionary
        try:
            self.actor_lookup = {}
            if os.path.exists(os.path.join(WORKING_DIR, "malpedia_actors.json")):
                with open(os.path.join(WORKING_DIR, "malpedia_actors.json")) as f:
                    self.actor_data = json.load(f)
            else:
                self.actor_data = requests.get(actors_url, timeout=5).json()
                with open(os.path.join(WORKING_DIR, "malpedia_actors.json"), "w") as f:
                    json.dump(self.actor_data, f)

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
        except requests.ConnectTimeout:
            pass
