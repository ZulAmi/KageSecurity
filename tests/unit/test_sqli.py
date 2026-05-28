"""Unit tests for scanner/modules/sqli.py helper functions and payload sets."""
import pytest
from scanner.modules.sqli import (
    _error_match,
    _extract_version_from_error,
    _get_payloads,
    ERROR_SIGNATURES,
    _WAF_BYPASS_ERROR,
    _WAF_BYPASS_UNION,
    _INJECTABLE_HEADERS,
    _DBMS_ERROR,
    _DBMS_BLIND,
)
from scanner.core.config import ScanConfig


class TestErrorMatch:
    def test_detects_mysql_error(self):
        body = "You have an error in your SQL syntax; check the manual"
        assert _error_match(body) is not None

    def test_detects_postgres_error(self):
        body = "PG::SyntaxError: ERROR:  syntax error at or near"
        assert _error_match(body) is not None

    def test_detects_mssql_error(self):
        body = "Unclosed quotation mark after the character string"
        assert _error_match(body) is not None

    def test_detects_oracle_error(self):
        body = "ORA-01756: quoted string not properly terminated"
        assert _error_match(body) is not None

    def test_no_match_on_clean_page(self):
        body = "<html><body>Welcome to our site. Please log in.</body></html>"
        assert _error_match(body) is None

    def test_case_insensitive(self):
        body = "WARNING: MySQL server has gone away"
        assert _error_match(body) is not None

    def test_returns_matched_signature(self):
        body = "syntax error near the end of the query"
        result = _error_match(body)
        assert result is not None
        assert isinstance(result, str)


class TestExtractVersion:
    def test_extracts_mysql_version(self):
        body = "MySQL 8.0.32 server error: table not found"
        v = _extract_version_from_error(body)
        assert v is not None
        assert "8.0" in v or "MySQL" in v

    def test_extracts_postgres_version(self):
        body = "ERROR: PostgreSQL 14.5 on x86_64 syntax error"
        v = _extract_version_from_error(body)
        assert v is not None
        assert "PostgreSQL" in v

    def test_returns_none_on_no_version(self):
        body = "Generic server error occurred"
        assert _extract_version_from_error(body) is None


class TestGetPayloads:
    def test_level1_caps_payloads(self):
        config = ScanConfig(target="http://x.com", level=1, risk=1)
        err, blind, union, bools = _get_payloads(config)
        assert len(err) <= 3
        assert len(union) <= 3

    def test_level3_more_payloads(self):
        config = ScanConfig(target="http://x.com", level=3, risk=2)
        err, blind, union, bools = _get_payloads(config)
        assert len(err) <= 10

    def test_risk1_no_blind(self):
        config = ScanConfig(target="http://x.com", risk=1)
        _, blind, _, _ = _get_payloads(config)
        assert blind == []

    def test_risk2_includes_blind(self):
        config = ScanConfig(target="http://x.com", risk=2)
        _, blind, _, _ = _get_payloads(config)
        assert len(blind) > 0

    def test_dbms_mysql_payloads(self):
        config = ScanConfig(target="http://x.com", dbms="mysql", risk=2, level=5)
        err, blind, _, _ = _get_payloads(config)
        assert any("SLEEP" in p or "EXTRACTVALUE" in p for p in err)

    def test_dbms_mssql_blind(self):
        config = ScanConfig(target="http://x.com", dbms="mssql", risk=2, level=5)
        _, blind, _, _ = _get_payloads(config)
        assert any("WAITFOR" in p for p in blind)

    def test_none_config_uses_defaults(self):
        err, blind, union, bools = _get_payloads(None)
        assert len(err) > 0
        assert blind == []


class TestWafBypassPayloads:
    def test_waf_bypass_error_not_empty(self):
        assert len(_WAF_BYPASS_ERROR) >= 3

    def test_waf_bypass_union_not_empty(self):
        assert len(_WAF_BYPASS_UNION) >= 3

    def test_waf_bypass_uses_comments(self):
        combined = " ".join(_WAF_BYPASS_ERROR + _WAF_BYPASS_UNION)
        assert "/**/" in combined or "/*!" in combined or "/*" in combined

    def test_waf_bypass_case_mutation(self):
        combined = " ".join(_WAF_BYPASS_UNION)
        assert any(c.isupper() and c != c.lower() for c in combined if c.isalpha())


class TestInjectableHeaders:
    def test_user_agent_included(self):
        assert "User-Agent" in _INJECTABLE_HEADERS

    def test_referer_included(self):
        assert "Referer" in _INJECTABLE_HEADERS

    def test_x_forwarded_for_included(self):
        assert "X-Forwarded-For" in _INJECTABLE_HEADERS


class TestDbmsPayloads:
    @pytest.mark.parametrize("dbms", ["mysql", "postgres", "mssql", "oracle", "sqlite"])
    def test_all_dbms_have_error_payloads(self, dbms):
        assert dbms in _DBMS_ERROR
        assert len(_DBMS_ERROR[dbms]) > 0

    @pytest.mark.parametrize("dbms", ["mysql", "postgres", "mssql", "oracle"])
    def test_major_dbms_have_blind_payloads(self, dbms):
        assert dbms in _DBMS_BLIND
        assert len(_DBMS_BLIND[dbms]) > 0
