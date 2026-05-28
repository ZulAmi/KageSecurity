"""Unit tests for scanner/core/template_runner.py — parsing and matcher logic."""
import os
import tempfile
import textwrap
import pytest
import yaml

from scanner.core.template_runner import (
    _parse_template,
    _parse_matcher,
    _parse_request,
    _extract_cve,
    TemplateMatcher,
    TemplateRequest,
)
from scanner.core.scan_result import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_template(content: str) -> str:
    f = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    f.write(textwrap.dedent(content))
    f.flush()
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Template parsing
# ---------------------------------------------------------------------------

class TestParseTemplate:
    def test_basic_template_loads(self):
        path = _write_template("""
            id: test-xss
            info:
              name: Test XSS
              severity: high
              description: XSS test
              remediation: sanitise input
            requests:
              - method: GET
                path:
                  - "{{BaseURL}}/?q=<script>"
                matchers-condition: and
                matchers:
                  - type: word
                    part: body
                    words: ["<script>"]
                  - type: status
                    status: [200]
        """)
        try:
            t = _parse_template(path)
            assert t is not None
            assert t.id == "test-xss"
            assert t.name == "Test XSS"
            assert t.severity == Severity.HIGH
            assert len(t.requests) == 1
            assert t.requests[0].matchers_condition == "and"
        finally:
            os.unlink(path)

    def test_cve_extracted_from_info(self):
        path = _write_template("""
            id: cve-test
            info:
              name: CVE Test
              severity: critical
              cve: CVE-2024-12345
              description: test
              remediation: upgrade
            requests:
              - method: GET
                path: ["{{BaseURL}}/"]
                matchers:
                  - type: status
                    status: [200]
        """)
        try:
            t = _parse_template(path)
            assert t.cve == "CVE-2024-12345"
        finally:
            os.unlink(path)

    def test_cve_extracted_from_tags(self):
        path = _write_template("""
            id: tagged-cve
            info:
              name: Tagged CVE
              severity: high
              tags: [apache, CVE-2023-99999, rce]
              description: test
              remediation: fix
            requests:
              - method: GET
                path: ["{{BaseURL}}/"]
                matchers:
                  - type: status
                    status: [200]
        """)
        try:
            t = _parse_template(path)
            assert t.cve == "CVE-2023-99999"
        finally:
            os.unlink(path)

    def test_severity_defaults_to_info(self):
        path = _write_template("""
            id: no-sev
            info:
              name: No Severity
              severity: unknown_value
              description: test
              remediation: fix
            requests:
              - method: GET
                path: ["{{BaseURL}}/"]
                matchers:
                  - type: status
                    status: [200]
        """)
        try:
            t = _parse_template(path)
            assert t.severity == Severity.INFO
        finally:
            os.unlink(path)

    def test_rate_limit_parsed(self):
        path = _write_template("""
            id: rate-limited
            info:
              name: Rate Limited
              severity: low
              description: test
              remediation: fix
            rate-limit: 2.5
            requests:
              - method: GET
                path: ["{{BaseURL}}/"]
                matchers:
                  - type: status
                    status: [200]
        """)
        try:
            t = _parse_template(path)
            assert t.rate_limit_rps == 2.5
        finally:
            os.unlink(path)

    def test_empty_yaml_returns_none(self):
        path = _write_template("")
        try:
            t = _parse_template(path)
            assert t is None
        finally:
            os.unlink(path)

    def test_no_requests_returns_none(self):
        path = _write_template("""
            id: no-requests
            info:
              name: No Requests
              severity: info
              description: test
              remediation: none
        """)
        try:
            t = _parse_template(path)
            assert t is None
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Matcher parsing
# ---------------------------------------------------------------------------

class TestParseMatcher:
    def test_status_matcher(self):
        m = _parse_matcher({"type": "status", "status": [200, 301]})
        assert m.type == "status"
        assert m.status == [200, 301]

    def test_word_matcher_defaults(self):
        m = _parse_matcher({"type": "word", "words": ["admin"]})
        assert m.type == "word"
        assert m.words == ["admin"]
        assert m.condition == "or"
        assert m.part == "body"
        assert m.negative is False

    def test_negative_matcher(self):
        m = _parse_matcher({"type": "word", "words": ["error"], "negative": True})
        assert m.negative is True

    def test_regex_matcher(self):
        m = _parse_matcher({"type": "regex", "regex": ["uid=\\d+"], "part": "body"})
        assert m.type == "regex"
        assert "uid=\\d+" in m.regex

    def test_and_condition(self):
        m = _parse_matcher({"type": "word", "words": ["a", "b"], "condition": "and"})
        assert m.condition == "and"


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

class TestExtractCve:
    def test_extracts_cve_from_tags(self):
        assert _extract_cve(["apache", "CVE-2021-44228", "rce"]) == "CVE-2021-44228"

    def test_returns_none_when_no_cve(self):
        assert _extract_cve(["apache", "rce", "log4j"]) is None

    def test_case_insensitive(self):
        result = _extract_cve(["cve-2023-1234"])
        assert result == "CVE-2023-1234"

    def test_empty_tags(self):
        assert _extract_cve([]) is None


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------

class TestParseRequest:
    def test_method_uppercased(self):
        r = _parse_request({"method": "post", "path": ["{{BaseURL}}/"]})
        assert r.method == "POST"

    def test_default_method_get(self):
        r = _parse_request({"path": ["{{BaseURL}}/"]})
        assert r.method == "GET"

    def test_matchers_condition_default_or(self):
        r = _parse_request({"path": ["{{BaseURL}}/"], "matchers": []})
        assert r.matchers_condition == "or"

    def test_matchers_condition_and(self):
        r = _parse_request({"path": ["{{BaseURL}}/"], "matchers-condition": "and"})
        assert r.matchers_condition == "and"

    def test_path_as_string_becomes_list(self):
        r = _parse_request({"path": "{{BaseURL}}/"})
        assert isinstance(r.paths, list)
        assert len(r.paths) == 1

    def test_payloads_parsed(self):
        r = _parse_request({
            "path": ["{{BaseURL}}/"],
            "payloads": {"payload1": ["a", "b", "c"]},
        })
        assert r.payloads == {"payload1": ["a", "b", "c"]}
