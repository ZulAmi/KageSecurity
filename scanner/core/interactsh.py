"""
Interactsh OOB client.

Interactsh (interact.sh) is the de-facto out-of-band interaction platform used
by the security community and recognised by bug bounty programs as proof of
blind injection (SSRF, XXE, blind SQLi, SSTI, Log4Shell, etc.).

This client:
  1. Registers a session with the public interactsh server
  2. Returns a unique subdomain to embed in payloads  (e.g. abc123.oast.fun)
  3. Polls for callbacks after modules finish
  4. Returns structured Interaction objects

No third-party library required — uses only urllib + standard crypto.

Public servers (any works):
  https://oast.fun   https://oast.pro   https://oast.me
  https://oast.live  https://oast.site

Self-hosted: pass server= to InteractshClient.__init__.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field


@dataclass
class Interaction:
    protocol: str           # dns | http | smtp | ldap
    unique_id: str          # which payload triggered this
    remote_address: str
    raw_request: str = ""
    raw_response: str = ""
    timestamp: str = ""


class InteractshClient:
    """
    Minimal interactsh client that speaks the public interactsh REST API.

    Usage:
        client = InteractshClient()
        domain = client.domain          # embed in payloads: ${jndi:ldap://domain/x}
        ...run scan...
        interactions = client.poll()    # list[Interaction]
        client.close()
    """

    _DEFAULT_SERVER = "oast.fun"

    def __init__(self, server: str | None = None):
        self._server = (server or self._DEFAULT_SERVER).rstrip("/")
        self._session_id: str | None = None
        self._correlation_id: str | None = None
        self._secret_key: str | None = None
        self.domain: str = ""
        self._registered = False
        self._register()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def _register(self) -> None:
        try:
            # Generate a random correlation ID (26 lower-case chars)
            self._correlation_id = base64.urlsafe_b64encode(
                os.urandom(20)
            ).decode().rstrip("=").lower()[:20]
            self._secret_key = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

            payload = json.dumps({
                "correlation-id": self._correlation_id,
                "secret-key": self._secret_key,
            }).encode()

            req = urllib.request.Request(
                f"https://{self._server}/register",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            self.domain = data.get("domain", f"{self._correlation_id}.{self._server}")
            self._registered = True
        except Exception:
            # Fall back to a predictable subdomain — polling will return nothing
            # but payloads can still be sent (OOB won't confirm, but doesn't crash)
            self._correlation_id = base64.urlsafe_b64encode(os.urandom(10)).decode()[:16].lower()
            self.domain = f"{self._correlation_id}.{self._server}"

    # ------------------------------------------------------------------
    # Unique subdomain per payload
    # ------------------------------------------------------------------

    def unique_domain(self) -> str:
        """Return a unique subdomain for embedding in a single payload."""
        unique = base64.urlsafe_b64encode(os.urandom(6)).decode()[:8].lower()
        return f"{unique}.{self.domain}"

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def poll(self, wait_seconds: int = 10) -> list[Interaction]:
        """Wait `wait_seconds` then poll once for callbacks."""
        if not self._registered:
            return []
        time.sleep(wait_seconds)
        return self._poll_once()

    def _poll_once(self) -> list[Interaction]:
        if not self._correlation_id or not self._secret_key:
            return []
        try:
            url = (
                f"https://{self._server}/poll"
                f"?id={self._correlation_id}&secret={self._secret_key}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "KageSec/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            interactions = []
            for item in data.get("data", []) or []:
                try:
                    raw = base64.b64decode(item).decode("utf-8", errors="ignore")
                    parsed = json.loads(raw)
                    interactions.append(Interaction(
                        protocol=parsed.get("protocol", "unknown"),
                        unique_id=parsed.get("unique-id", self._correlation_id or ""),
                        remote_address=parsed.get("remote-address", ""),
                        raw_request=parsed.get("raw-request", ""),
                        raw_response=parsed.get("raw-response", ""),
                        timestamp=parsed.get("timestamp", ""),
                    ))
                except Exception:
                    continue
            return interactions
        except Exception:
            return []

    def close(self):
        """Deregister the session from the server."""
        if not self._registered or not self._correlation_id:
            return
        try:
            payload = json.dumps({
                "correlation-id": self._correlation_id,
                "secret-key": self._secret_key,
            }).encode()
            req = urllib.request.Request(
                f"https://{self._server}/deregister",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Drop-in replacement for the old OOBServer interface used by engine.py
# ---------------------------------------------------------------------------

class OOBServer:
    """
    Compatibility shim — wraps InteractshClient with the same interface
    as the old scanner/core/oob.py OOBServer.

    engine.py calls:
        oob = OOBServer(server=...)
        canary = oob.get_canary()
        interactions = oob.poll(wait_seconds=15)
        oob.close()
    """

    def __init__(self, server: str | None = None):
        self._client = InteractshClient(server=server or None)

    def get_canary(self) -> str:
        return self._client.domain

    def unique_canary(self) -> str:
        return self._client.unique_domain()

    def poll(self, wait_seconds: int = 15) -> list[Interaction]:
        return self._client.poll(wait_seconds=wait_seconds)

    def close(self):
        self._client.close()
