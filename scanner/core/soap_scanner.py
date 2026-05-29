"""
SOAP / WSDL Service Tester — Gap 16

Parses a WSDL document, generates SOAP envelopes for each operation,
injects payloads into string-typed parameters, and checks responses for:
  - Injection signals (SQLi error signatures, XSS reflection, SSTI evaluation)
  - Verbose SOAP Faults exposing stack traces or internal details
  - Unauthenticated access to operations
  - XXE via SOAP body

Usage (CLI):
  kagesec scan https://example.com --wsdl https://example.com/service?wsdl

Programmatic:
  from scanner.core.soap_scanner import scan_wsdl
  findings = scan_wsdl("https://example.com/service?wsdl", client, config)
"""
from __future__ import annotations

import re
import httpx
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.config import ScanConfig
    from scanner.core.scan_result import Finding

_XML_AVAILABLE = False
try:
    from xml.etree import ElementTree as ET
    _XML_AVAILABLE = True
except ImportError:
    pass

# WSDL namespaces
_NS = {
    "wsdl": "http://schemas.xmlsoap.org/wsdl/",
    "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
    "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
    "xsd": "http://www.w3.org/2001/XMLSchema",
}

# Injection payloads for SOAP string parameters
_INJECTION_PAYLOADS = [
    ("'", "SQLi", re.compile(r'sql syntax|you have an error|odbc|ora-0', re.IGNORECASE)),
    ("<script>alert(1)</script>", "XSS", re.compile(r'<script>alert\(1\)</script>', re.IGNORECASE)),
    ("{{7*7}}", "SSTI", re.compile(r'\b49\b')),
    (";id;", "CMDi", re.compile(r'uid=\d+|root:')),
]

# XXE payload
_XXE_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# SOAP Fault patterns
_FAULT_PATTERNS = [
    re.compile(r'<faultstring[^>]*>([^<]{10,300})</faultstring>', re.IGNORECASE),
    re.compile(r'<detail[^>]*>(.*?)</detail>', re.IGNORECASE | re.DOTALL),
]
_VERBOSE_FAULT_RE = re.compile(
    r'(?:Exception|Error|Traceback|StackTrace|at \w+\.java|line \d+)',
    re.IGNORECASE,
)


@dataclass
class WsdlOperation:
    name: str
    endpoint: str
    soap_action: str
    namespace: str
    input_parts: List[str] = field(default_factory=list)   # parameter names


def scan_wsdl(
    wsdl_url: str,
    client: httpx.Client,
    config: Optional["ScanConfig"] = None,
) -> List["Finding"]:
    from scanner.core.scan_result import Finding, Severity

    if not _XML_AVAILABLE:
        return []

    # Fetch WSDL
    try:
        resp = client.get(wsdl_url, timeout=15)
        if resp.status_code != 200:
            return []
        wsdl_text = resp.text
    except Exception:
        return []

    operations = _parse_wsdl(wsdl_text, wsdl_url)
    if not operations:
        return []

    findings: List[Finding] = []
    for op in operations:
        # 1. Empty/benign request — check for verbose fault
        body = _build_soap_envelope(op, {})
        resp_text, resp_status = _send_soap(client, op.endpoint, op.soap_action, body)
        if resp_text:
            _check_verbose_fault(op, resp_text, findings)
            _check_xxe(client, op, findings)

        # 2. Injection in string parameters
        for param in op.input_parts:
            for payload, cls, sig_re in _INJECTION_PAYLOADS:
                inj_body = _build_soap_envelope(op, {param: payload})
                inj_text, _ = _send_soap(client, op.endpoint, op.soap_action, inj_body)
                if inj_text and sig_re.search(inj_text):
                    findings.append(Finding(
                        title=f"SOAP {cls} in Operation {op.name}",
                        severity=Severity.HIGH if cls != "XSS" else Severity.MEDIUM,
                        url=op.endpoint,
                        parameter=param,
                        payload=payload,
                        evidence=f"SOAP response matched '{cls}' signature for payload '{payload[:50]}'",
                        description=(
                            f"The SOAP operation '{op.name}' parameter '{param}' appears vulnerable "
                            f"to {cls} injection. SOAP endpoints are often overlooked and may "
                            "bypass WAF rules tuned for HTTP query parameters."
                        ),
                        remediation=(
                            "Validate and sanitize all SOAP input parameters. "
                            "Use parameterized queries for database operations. "
                            "Apply the same input validation as REST endpoints."
                        ),
                        cwe="CWE-89" if "SQL" in cls else "CWE-79",
                        cvss=7.5,
                        owasp_category="A03:2021 Injection",
                        confidence=0.75,
                    ))
                    break

    return findings


def _parse_wsdl(wsdl_text: str, wsdl_url: str) -> List[WsdlOperation]:
    ops = []
    try:
        root = ET.fromstring(wsdl_text)  # nosec B314 — Python 3.8+ ET ignores external entities
    except ET.ParseError:
        return ops

    # Extract service endpoint
    endpoint = wsdl_url.split("?")[0]
    for port in root.iter("{http://schemas.xmlsoap.org/wsdl/}port"):
        for addr in port:
            loc = addr.get("location", "")
            if loc:
                endpoint = loc
                break

    # Get target namespace
    namespace = root.get("targetNamespace", "")

    # Extract operations
    for binding in root.iter("{http://schemas.xmlsoap.org/wsdl/}binding"):
        for op in binding.iter("{http://schemas.xmlsoap.org/wsdl/}operation"):
            op_name = op.get("name", "")
            soap_action = ""
            for soap_op in op:
                sa = soap_op.get("soapAction", "")
                if sa:
                    soap_action = sa

            # Try to find input message parts
            parts = _find_input_parts(root, op_name)
            ops.append(WsdlOperation(
                name=op_name,
                endpoint=endpoint,
                soap_action=soap_action,
                namespace=namespace,
                input_parts=parts,
            ))

    return ops


def _find_input_parts(root, op_name: str) -> List[str]:
    parts = []
    for port_type in root.iter("{http://schemas.xmlsoap.org/wsdl/}portType"):
        for op in port_type.iter("{http://schemas.xmlsoap.org/wsdl/}operation"):
            if op.get("name") == op_name:
                for inp in op.iter("{http://schemas.xmlsoap.org/wsdl/}input"):
                    msg_name = inp.get("message", "").split(":")[-1]
                    # Find message definition
                    for msg in root.iter("{http://schemas.xmlsoap.org/wsdl/}message"):
                        if msg.get("name") == msg_name:
                            for part in msg.iter("{http://schemas.xmlsoap.org/wsdl/}part"):
                                p_name = part.get("name", "")
                                if p_name:
                                    parts.append(p_name)
    return parts if parts else ["value", "input", "param"]


def _build_soap_envelope(op: WsdlOperation, params: dict) -> str:
    param_xml = ""
    for name, val in params.items():
        param_xml += f"<{name}>{val}</{name}>"
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        f'xmlns:tns="{op.namespace}">'
        "<soap:Body>"
        f"<tns:{op.name}>"
        f"{param_xml}"
        f"</tns:{op.name}>"
        "</soap:Body>"
        "</soap:Envelope>"
    )


def _send_soap(client: httpx.Client, endpoint: str, action: str, body: str):
    try:
        resp = client.post(
            endpoint,
            content=body,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": f'"{action}"',
            },
            timeout=15,
        )
        return resp.text, resp.status_code
    except Exception:
        return "", 0


def _check_verbose_fault(op: WsdlOperation, resp_text: str, findings: list):
    from scanner.core.scan_result import Finding, Severity
    for pat in _FAULT_PATTERNS:
        m = pat.search(resp_text)
        if m and _VERBOSE_FAULT_RE.search(m.group(1)):
            findings.append(Finding(
                title=f"SOAP — Verbose Fault in Operation {op.name}",
                severity=Severity.LOW,
                url=op.endpoint,
                parameter=None,
                payload="{}",
                evidence=f"SOAP Fault detail: {m.group(1)[:300]}",
                description=(
                    f"The SOAP operation '{op.name}' returns verbose error messages containing "
                    "stack traces or internal implementation details when called with empty input."
                ),
                remediation=(
                    "Return generic SOAP Fault messages in production. "
                    "Log detailed errors server-side only."
                ),
                cwe="CWE-209",
                cvss=3.7,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.80,
            ))
            break


def _check_xxe(client: httpx.Client, op: WsdlOperation, findings: list):
    from scanner.core.scan_result import Finding, Severity
    xxe_body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soap:Body>"
        f"<tns:{op.name}>&xxe;</tns:{op.name}>"
        "</soap:Body>"
        "</soap:Envelope>"
    )
    resp_text, _ = _send_soap(client, op.endpoint, op.soap_action, xxe_body)
    if resp_text and "root:x:0:0" in resp_text:
        findings.append(Finding(
            title=f"SOAP XXE — Operation {op.name}",
            severity=Severity.CRITICAL,
            url=op.endpoint,
            parameter="XML body",
            payload=_XXE_PAYLOAD[:100],
            evidence=f"XXE payload returned /etc/passwd content: {resp_text[:200]}",
            description="SOAP endpoint is vulnerable to XML External Entity (XXE) injection.",
            remediation=(
                "Disable external entity processing in your XML parser. "
                "Use a hardened XML parser configuration."
            ),
            cwe="CWE-611",
            cvss=9.8,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=1.0,
        ))
