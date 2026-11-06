import os
import ssl
import urllib.request

scheme = "https" if os.environ.get("COMPLY_TLS", "false") == "true" else "http"
port = os.environ.get("COMPLY_PORT", "8080")
urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/health", timeout=4,
                       context=ssl._create_unverified_context())
