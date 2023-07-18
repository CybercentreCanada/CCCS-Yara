import os
from pathlib import Path

# set current working directory
SCRIPT_LOCATION = Path(__file__).resolve().parent
VALIDATOR_CFG = os.environ.get('VALIDATOR_CFG', SCRIPT_LOCATION / 'validator_cfg.yml')

# Allow use of custom paths/configurations besides the defaults
CONFIG_YAML_PATH = os.environ.get('CONFIG_YAML_PATH', SCRIPT_LOCATION / 'CCCS_YARA.yml')
CONFIG_VALUES_YAML_PATH = os.environ.get('CONFIG_VALUES_YAML_PATH', SCRIPT_LOCATION / 'CCCS_YARA_values.yml')
MITRE_STIX_DATA_PATH = os.environ.get('MITRE_STIX_DATA_PATH', SCRIPT_LOCATION / 'cti')
