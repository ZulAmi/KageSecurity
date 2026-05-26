"""
Out-of-Band (OOB) callback client using the interactsh protocol.

Registers a unique subdomain on an interactsh-compatible server (default: oast.pro).
Modules inject the canary URL into payloads; after modules run, poll() checks whether
the target triggered a DNS or HTTP callback — confirming blind injection vulnerabilities
that can't be detected by inspecting the response body alone.

Usage:
    oob = OOBServer()
    canary = oob.get_canary()         # e.g. "abc123.oast.pro"
    # ... inject canary into payloads ...
    interactions = oob.poll(wait_seconds=15)
    oob.close()
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import List, Optional

import httpx


@dataclass
class OOBInteraction:
    protocol: str           # "dns" | "http" | "smtp"
    remote_address: str
    raw_request: str = ""
    timestamp: str = ""
    unique_id: str = ""


class OOBServer:
    """
    Interactsh-compatible OOB callback server client.

    Registers a unique correlation ID with the server, builds a canary hostname,
    and polls for interactions after payloads are sent.

    If the interactsh server is unreachable (e.g. no internet), falls back to
    a no-op mode so scans still run — blind vulns just won't be confirmed.
    """

    _REGISTER_PATH = "/register"
    _POLL_PATH = "/poll"

    def __init__(self, server: str = "oast.pro"):
        self._server = server
        self._base_url = f"https://{server}"
        self._client = httpx.Client(timeout=10, follow_redirects=True)
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._canary: Optional[str] = None
        self._available = False

        self._register()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_canary(self) -> str:
        """Return the unique hostname to embed in payloads."""
        if self._canary:
            return self._canary
        # Fallback: a random subdomain that won't resolve but won't error
        return f"kagesec-oob-{secrets.token_hex(8)}.invalid"

    def poll(self, wait_seconds: int = 10) -> List[OOBInteraction]:
        """
        Wait `wait_seconds` then query the server for interactions.
        Returns list of interactions matching our correlation ID.
        """
        if not self._available or not self._correlation_id:
            return []

        time.sleep(wait_seconds)

        try:
            resp = self._client.get(
                f"{self._base_url}{self._POLL_PATH}",
                params={
                    "id": self._correlation_id,
                    "secret": self._secret_key,
                },
                timeout=15,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            interactions = []
            for item in data.get("data", []) or []:
                try:
                    # Interactsh AES-encrypted payload — decrypt if needed
                    # For simplicity we work with the plain metadata fields
                    protocol = item.get("protocol", "dns")
                    remote = item.get("remote-address", item.get("remote_address", ""))
                    interactions.append(OOBInteraction(
                        protocol=protocol,
                        remote_address=remote,
                        raw_request=item.get("raw-request", ""),
                        timestamp=item.get("timestamp", ""),
                        unique_id=item.get("unique-id", ""),
                    ))
                except Exception:
                    continue
            return interactions

        except Exception:
            return []

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _register(self):
        """Register with the interactsh server to obtain a correlation ID."""
        try:
            self._correlation_id = secrets.token_hex(16)
            self._secret_key = secrets.token_hex(32)

            payload = {
                "public-key": self._make_public_key(),
                "secret-key": self._secret_key,
                "correlation-id": self._correlation_id,
            }

            resp = self._client.post(
                f"{self._base_url}{self._REGISTER_PATH}",
                json=payload,
                timeout=10,
            )

            if resp.status_code == 200:
                self._canary = f"{self._correlation_id}.{self._server}"
                self._available = True
            else:
                # Server reachable but rejected — use fallback
                self._canary = f"kagesec-{self._correlation_id[:8]}.{self._server}"
                self._available = False

        except Exception:
            # Server unreachable — degrade gracefully
            self._canary = f"kagesec-oob-{secrets.token_hex(8)}.invalid"
            self._available = False

    def _make_public_key(self) -> str:
        """
        Generate a minimal RSA-like placeholder public key for interactsh registration.
        In production, this should be a real RSA-2048 public key for response decryption.
        We use a placeholder since we only need the correlation ID for DNS detection.
        """
        # Interactsh requires a base64-encoded public key; use a stable placeholder
        import base64
        placeholder = f"kagesec-pubkey-{self._correlation_id}".encode()
        return base64.b64encode(placeholder).decode()
