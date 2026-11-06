"""Central configuration. All values come from environment variables (.env)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

APP_NAME = "1cyber Comply"
APP_VERSION = "0.3.2"

# SQLite database (a single file, no separate server)
DATA_DIR = Path(os.getenv("COMPLY_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "comply.db"

# Folder with the control catalogues (YAML)
CONTROLS_DIR = Path(os.getenv("COMPLY_CONTROLS_DIR", BASE_DIR / "controls"))

# Wazuh Server API
WAZUH_URL = os.getenv("WAZUH_URL", "")
WAZUH_USER = os.getenv("WAZUH_USER", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"

# Wazuh Indexer (alerts and vulnerabilities, port 9200). Optional.
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")

# Check thresholds (adjustable per organisation)
SCA_MIN_SCORE = int(os.getenv("SCA_MIN_SCORE", "70"))          # minimum SCA % per agent
FIM_MAX_AGE_HOURS = int(os.getenv("FIM_MAX_AGE_HOURS", "48"))  # max age of the last FIM scan
ALERTS_WINDOW_DAYS = int(os.getenv("ALERTS_WINDOW_DAYS", "30"))

# OPNsense API
OPNSENSE_URL = os.getenv("OPNSENSE_URL", "")
OPNSENSE_KEY = os.getenv("OPNSENSE_KEY", "")
OPNSENSE_SECRET = os.getenv("OPNSENSE_SECRET", "")
OPNSENSE_VERIFY_TLS = os.getenv("OPNSENSE_VERIFY_TLS", "false").lower() == "true"
