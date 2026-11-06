"""Configurare centrala. Toate valorile vin din variabile de mediu (.env)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

APP_NAME = "1cyber Comply"
APP_VERSION = "0.3.0"

# Baza de date SQLite (un singur fisier, fara server separat)
DATA_DIR = Path(os.getenv("COMPLY_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "comply.db"

# Folderul cu cataloagele de controale (YAML)
CONTROLS_DIR = Path(os.getenv("COMPLY_CONTROLS_DIR", BASE_DIR / "controls"))

# Wazuh API (folosit din etapa 2)
WAZUH_URL = os.getenv("WAZUH_URL", "")
WAZUH_USER = os.getenv("WAZUH_USER", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"

# Wazuh Indexer (alerte si vulnerabilitati, port 9200). Optional.
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")

# Praguri pentru verificari (ajustabile per client)
SCA_MIN_SCORE = int(os.getenv("SCA_MIN_SCORE", "70"))          # % minim SCA per agent
FIM_MAX_AGE_HOURS = int(os.getenv("FIM_MAX_AGE_HOURS", "48"))  # ultima scanare FIM
ALERTS_WINDOW_DAYS = int(os.getenv("ALERTS_WINDOW_DAYS", "30"))

# OPNsense API (folosit din etapa 2)
OPNSENSE_URL = os.getenv("OPNSENSE_URL", "")
OPNSENSE_KEY = os.getenv("OPNSENSE_KEY", "")
OPNSENSE_SECRET = os.getenv("OPNSENSE_SECRET", "")
OPNSENSE_VERIFY_TLS = os.getenv("OPNSENSE_VERIFY_TLS", "false").lower() == "true"
