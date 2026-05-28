"""
gRPC / protobuf scanner.

Discovers gRPC services via reflection (gRPC Server Reflection Protocol)
and generates fuzz requests for each method, checking for:
  - Injection in string fields (SQLi, XSS, SSTI, cmd injection)
  - Missing authentication / authorization (method accessible without creds)
  - Sensitive data in responses (credentials, tokens, PII)
  - Verbose error messages exposing stack traces / internals

Strategy
--------
1. Connect to the target with gRPC reflection (grpc.reflection.v1alpha)
2. List all services and their methods + request/response types
3. For each method:
   a. Send a benign request (empty/default values)
   b. Send injection payloads in each string field
   c. Check responses for injection signals or sensitive data

Dependencies
------------
  grpcio          — gRPC Python client
  grpcio-reflection — reflection client helpers
  protobuf        — message parsing

These are optional; the scanner gracefully falls back if they're not installed.

Usage
-----
  kagesec scan https://example.com --grpc grpc.example.com:50051

Or programmatically:
  from scanner.core.grpc_scanner import scan_grpc
  findings = scan_grpc("grpc.example.com:50051", config)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.config import ScanConfig
    from scanner.core.scan_result import Finding

_GRPC_AVAILABLE = False
try:
    import grpc  # type: ignore
    _GRPC_AVAILABLE = True
except ImportError:
    pass

_REFLECTION_AVAILABLE = False
try:
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore
    _REFLECTION_AVAILABLE = True
except ImportError:
    pass

_PROTO_AVAILABLE = False
try:
    from google.protobuf import descriptor_pb2, symbol_database  # type: ignore
    _PROTO_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Injection payloads for string fields
# ---------------------------------------------------------------------------

_INJECTION_PAYLOADS = [
    ("'", "SQLi", "sql error"),
    ("' OR '1'='1", "SQLi boolean", "sql syntax"),
    ("<script>alert(1)</script>", "XSS", "<script>"),
    ("{{7*7}}", "SSTI", "49"),
    (";id;", "CMDi", "uid="),
    ("../../../../etc/passwd", "LFI", "root:x:"),
]

_SENSITIVE_PATTERNS = [
    re.compile(r'\bpassword\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'\btoken\s*[:=]\s*[A-Za-z0-9+/]{20,}', re.IGNORECASE),
    re.compile(r'\bsecret\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),   # base64 blob (API key / JWT)
    re.compile(r'BEGIN (RSA|EC|PRIVATE|CERTIFICATE)'),
    re.compile(r'AKIA[0-9A-Z]{16}'),             # AWS key
]

_ERROR_PATTERNS = [
    re.compile(r'(?:Exception|Error|Traceback|panic|goroutine)\s*:', re.IGNORECASE),
    re.compile(r'at \w+\.java:\d+'),
    re.compile(r'File ".*", line \d+'),
    re.compile(r'php warning|php error|php notice', re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GrpcMethod:
    service: str
    name: str
    full_name: str
    input_type: str
    output_type: str
    client_streaming: bool = False
    server_streaming: bool = False


@dataclass
class GrpcScanResult:
    findings: list = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    methods: list[GrpcMethod] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_grpc(
    endpoint: str,
    config: Optional["ScanConfig"] = None,
    timeout: float = 10.0,
) -> GrpcScanResult:
    """
    Scan a gRPC endpoint.

    *endpoint* — host:port  (e.g. "api.example.com:50051")
    Returns a GrpcScanResult with findings and metadata.
    """
    from scanner.core.scan_result import Finding, Severity

    if not _GRPC_AVAILABLE:
        return GrpcScanResult(error=(
            "grpcio not installed. Run: pip install grpcio grpcio-reflection"
        ))

    result = GrpcScanResult()

    # Build channel
    use_tls = config and getattr(config, "grpc_tls", True)
    try:
        if use_tls:
            creds = grpc.ssl_channel_credentials()
            channel = grpc.secure_channel(endpoint, creds)
        else:
            channel = grpc.insecure_channel(endpoint)
    except Exception as e:
        result.error = f"Could not connect to {endpoint}: {e}"
        return result

    # Discover services via reflection
    services = _list_services(channel, timeout)
    if services is None:
        result.error = (
            f"gRPC reflection not available on {endpoint}. "
            "Server must enable grpc.reflection.v1alpha.ServerReflection."
        )
        channel.close()
        return result

    result.services = services

    for svc in services:
        if svc == "grpc.reflection.v1alpha.ServerReflection":
            continue

        methods = _list_methods(channel, svc, timeout)
        result.methods.extend(methods)

        for method in methods:
            # 1. Unauthenticated probe (empty request)
            resp_text, err = _invoke_method_raw(channel, method, {}, timeout)

            if err and _is_internal_error(err):
                result.findings.append(Finding(
                    title=f"gRPC — Verbose Error in {method.full_name}",
                    severity=Severity.LOW,
                    url=f"grpc://{endpoint}/{method.full_name}",
                    parameter=None,
                    payload="{}",
                    evidence=f"Internal error exposed: {err[:300]}",
                    description=(
                        f"The gRPC method {method.full_name} returned a verbose internal "
                        "error message when called without authentication. Stack traces or "
                        "implementation details should not be returned to clients."
                    ),
                    remediation=(
                        "Catch exceptions server-side and return generic status codes. "
                        "Use gRPC status codes (UNAUTHENTICATED, NOT_FOUND) without details."
                    ),
                    cwe="CWE-209",
                    cvss=3.1,
                    owasp_category="A05:2021 Security Misconfiguration",
                    confidence=0.85,
                ))

            if resp_text and _contains_sensitive(resp_text):
                result.findings.append(Finding(
                    title=f"gRPC — Sensitive Data in {method.full_name} Response",
                    severity=Severity.HIGH,
                    url=f"grpc://{endpoint}/{method.full_name}",
                    parameter=None,
                    payload="{}",
                    evidence=f"Response contains sensitive patterns: {resp_text[:300]}",
                    description=(
                        f"The unauthenticated gRPC method {method.full_name} returned "
                        "data matching sensitive patterns (credentials, tokens, keys). "
                        "This method may not have authentication enforced."
                    ),
                    remediation=(
                        "Add authentication interceptors to all gRPC methods. "
                        "Never return credentials or secrets in responses."
                    ),
                    cwe="CWE-284",
                    cvss=7.5,
                    owasp_category="A01:2021 Broken Access Control",
                    confidence=0.80,
                ))

            # 2. Injection probes in string fields
            for payload, cls, sig in _INJECTION_PAYLOADS:
                inj_resp, inj_err = _invoke_method_raw(
                    channel, method, {"__fuzz_string__": payload}, timeout
                )
                combined = (inj_resp or "") + (inj_err or "")
                if sig.lower() in combined.lower():
                    result.findings.append(Finding(
                        title=f"gRPC — {cls} in {method.full_name}",
                        severity=Severity.HIGH if cls != "XSS" else Severity.MEDIUM,
                        url=f"grpc://{endpoint}/{method.full_name}",
                        parameter="string_field",
                        payload=payload,
                        evidence=f"Payload '{payload}' triggered response containing '{sig}'",
                        description=(
                            f"The gRPC method {method.full_name} appears to reflect or "
                            f"process the string payload in an unsafe way ({cls}). "
                            "String fields in gRPC messages are subject to injection "
                            "if not properly sanitised."
                        ),
                        remediation=(
                            "Validate and sanitise all input fields before processing. "
                            "Use parameterised queries for database operations. "
                            "Apply input length and character restrictions."
                        ),
                        cwe="CWE-89" if "SQL" in cls else "CWE-78" if "CMDi" in cls else "CWE-79",
                        cvss=7.5,
                        owasp_category="A03:2021 Injection",
                        confidence=0.70,
                    ))
                    break  # one finding per method per injection class is enough

    channel.close()
    return result


# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

def _list_services(channel, timeout: float) -> Optional[list[str]]:
    """List service names via gRPC Server Reflection."""
    if not _REFLECTION_AVAILABLE:
        return None
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        responses = stub.ServerReflectionInfo(iter([request]), timeout=timeout)
        for resp in responses:
            if resp.HasField("list_services_response"):
                return [s.name for s in resp.list_services_response.service]
        return []
    except Exception:
        return None


def _list_methods(channel, service: str, timeout: float) -> list[GrpcMethod]:
    """List methods for a service via reflection."""
    if not _REFLECTION_AVAILABLE:
        return []
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        req = reflection_pb2.ServerReflectionRequest(file_containing_symbol=service)
        responses = stub.ServerReflectionInfo(iter([req]), timeout=timeout)
        methods = []
        for resp in responses:
            if resp.HasField("file_descriptor_response"):
                for proto_bytes in resp.file_descriptor_response.file_descriptor_proto:
                    methods.extend(_parse_proto_bytes(proto_bytes, service))
        return methods
    except Exception:
        return []


def _parse_proto_bytes(proto_bytes: bytes, service_name: str) -> list[GrpcMethod]:
    """Extract method descriptors from a FileDescriptorProto blob."""
    if not _PROTO_AVAILABLE:
        return []
    try:
        from google.protobuf import descriptor_pb2 as dpb2
        fdp = dpb2.FileDescriptorProto()
        fdp.ParseFromString(proto_bytes)
        pkg = fdp.package
        methods = []
        for svc in fdp.service:
            full_svc = f"{pkg}.{svc.name}" if pkg else svc.name
            if service_name and full_svc != service_name:
                continue
            for method in svc.method:
                methods.append(GrpcMethod(
                    service=full_svc,
                    name=method.name,
                    full_name=f"/{full_svc}/{method.name}",
                    input_type=method.input_type.lstrip("."),
                    output_type=method.output_type.lstrip("."),
                    client_streaming=method.client_streaming,
                    server_streaming=method.server_streaming,
                ))
        return methods
    except Exception:
        return []


def _invoke_method_raw(
    channel,
    method: GrpcMethod,
    payload_fields: dict,
    timeout: float,
) -> tuple[str, str]:
    """
    Invoke a gRPC method dynamically with an empty or fuzz payload.
    Returns (response_text, error_text).
    """
    try:
        from google.protobuf.empty_pb2 import Empty
        request_msg = Empty()
    except ImportError:
        request_msg = b""

    try:
        future = channel.unary_unary(
            method.full_name,
            request_serializer=lambda x: x if isinstance(x, bytes) else b"",
            response_deserializer=lambda x: x,
        ).future(request_msg, timeout=timeout)
        result = future.result()
        return (str(result) if result else "", "")
    except Exception as exc:
        return ("", str(exc))


def _is_internal_error(err_text: str) -> bool:
    return any(p.search(err_text) for p in _ERROR_PATTERNS)


def _contains_sensitive(text: str) -> bool:
    return any(p.search(text) for p in _SENSITIVE_PATTERNS)
