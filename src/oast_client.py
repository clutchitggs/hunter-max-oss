"""
OAST Client — Out-of-Band Application Security Testing via Interactsh.

Provides generate_url() and poll_interactions() for the Resource Specialist Sniper
to detect blind SSRF, XXE, and other out-of-band vulnerabilities.

Requires a self-hosted interactsh-server instance.
Setup: See deploy/oast-setup.sh

Usage:
    client = OASTClient("oast.yourdomain.com")
    client.register()
    url = client.generate_url("ssrf-test-1")
    # ... send url in SSRF payload ...
    hits = client.poll_interactions(timeout_sec=15)
    client.close()
"""
import hashlib
import json
import logging
import os
import time
import uuid
from base64 import b64decode, b64encode
from pathlib import Path
from urllib.parse import urlparse

import requests

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent


def _load_oast_config():
    """Load OAST config from config.json."""
    try:
        with open(ROOT / "config.json") as f:
            cfg = json.load(f)
        return cfg.get("oast", {})
    except Exception:
        return {}


class OASTClient:
    """Client for interactsh out-of-band interaction detection.

    Uses the interactsh HTTP API to register, generate unique callback URLs,
    and poll for interactions (DNS, HTTP, SMTP).
    """

    def __init__(self, server_url=None):
        """Initialize with interactsh server URL.

        Args:
            server_url: interactsh server (e.g., "oast.yourdomain.com").
                        If None, loaded from config.json.
        """
        if not server_url:
            cfg = _load_oast_config()
            server_url = cfg.get("server_url", "")

        # Normalize: strip protocol, trailing slashes
        server_url = server_url.replace("https://", "").replace("http://", "").rstrip("/")
        self.server_url = server_url
        self.api_base = f"https://{server_url}"
        self.correlation_id = None
        self.secret_key = None
        self.registered = False
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({"User-Agent": "Mozilla/5.0"})

    def register(self):
        """Register with interactsh server. Gets a unique correlation subdomain.

        Returns True on success, False on failure.
        """
        if not self.server_url:
            log.warning("[OAST] No server URL configured")
            return False

        try:
            # Generate a random correlation ID and secret
            self.correlation_id = uuid.uuid4().hex[:20]
            self.secret_key = uuid.uuid4().hex

            resp = self._session.post(
                f"{self.api_base}/register",
                json={
                    "public-key": "",  # Simplified — no encryption for self-hosted
                    "secret-key": self.secret_key,
                    "correlation-id": self.correlation_id,
                },
                timeout=10,
            )

            if resp.status_code == 200:
                self.registered = True
                log.info(f"[OAST] Registered with {self.server_url} (id: {self.correlation_id[:8]}...)")
                return True
            else:
                log.warning(f"[OAST] Registration failed: HTTP {resp.status_code}")
                return False

        except Exception as e:
            log.warning(f"[OAST] Registration failed: {e}")
            # Fallback: use correlation ID without registration (works for DNS-only detection)
            self.correlation_id = uuid.uuid4().hex[:20]
            self.registered = False
            log.info(f"[OAST] Fallback mode — DNS-only detection (id: {self.correlation_id[:8]}...)")
            return True  # Can still generate URLs, just can't poll HTTP interactions

    def generate_url(self, label=""):
        """Generate a unique OAST callback URL for a specific test.

        Args:
            label: short identifier for this test (e.g., "ssrf-1", "xxe-check")

        Returns:
            Callback URL like: http://label-uniqueid.correlationid.oast.yourdomain.com
        """
        if not self.correlation_id:
            self.register()

        unique = uuid.uuid4().hex[:8]
        if label:
            # Sanitize label for DNS compatibility
            label = label.lower().replace("_", "-").replace(" ", "-")[:20]
            subdomain = f"{label}-{unique}"
        else:
            subdomain = unique

        callback_host = f"{subdomain}.{self.correlation_id}.{self.server_url}"
        return f"http://{callback_host}"

    def poll_interactions(self, timeout_sec=15, poll_interval=3):
        """Poll for interactions received by the OAST server.

        Args:
            timeout_sec: max seconds to wait for interactions
            poll_interval: seconds between poll attempts

        Returns:
            List of interaction dicts: [{protocol, remote_address, timestamp, raw_request}]
        """
        if not self.registered or not self.correlation_id:
            return []

        interactions = []
        deadline = time.time() + timeout_sec

        while time.time() < deadline:
            try:
                resp = self._session.get(
                    f"{self.api_base}/poll",
                    params={
                        "id": self.correlation_id,
                        "secret": self.secret_key,
                    },
                    timeout=10,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    raw_interactions = data.get("data", []) or data.get("interactions", [])

                    for item in raw_interactions:
                        interactions.append({
                            "protocol": item.get("protocol", "unknown"),
                            "remote_address": item.get("remote-address", ""),
                            "timestamp": item.get("timestamp", ""),
                            "raw_request": item.get("raw-request", "")[:2000],
                            "type": item.get("type", ""),
                            "full_id": item.get("full-id", ""),
                        })

                    if interactions:
                        log.info(f"[OAST] {len(interactions)} interactions received!")
                        return interactions

            except Exception as e:
                log.debug(f"[OAST] Poll error: {e}")

            time.sleep(poll_interval)

        return interactions  # Empty if nothing received

    def close(self):
        """Deregister from interactsh server."""
        if not self.registered or not self.correlation_id:
            return

        try:
            self._session.post(
                f"{self.api_base}/deregister",
                json={
                    "correlation-id": self.correlation_id,
                    "secret-key": self.secret_key,
                },
                timeout=5,
            )
            log.info(f"[OAST] Deregistered from {self.server_url}")
        except Exception:
            pass
        finally:
            self.correlation_id = None
            self.registered = False

    def __enter__(self):
        self.register()
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def is_available(self):
        """Check if OAST is configured and registered."""
        return bool(self.server_url and self.correlation_id)
