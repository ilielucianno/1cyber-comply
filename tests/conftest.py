import os
import tempfile

# Isolated database and no background scheduler during tests.
os.environ.setdefault("COMPLY_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("COLLECT_INTERVAL_HOURS", "0")
