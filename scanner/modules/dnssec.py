import socket
from urllib.parse import urlparse
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_checked_domains: set = set()


def test(page: CrawlResult, client) -> List[Finding]:
    domain = urlparse(page.url).netloc.split(":")[0]
    if domain in _checked_domains:
        return []
    _checked_domains.add(domain)

    # Try dnspython if available, else fall back to basic check
    try:
        return _check_with_dnspython(domain)
    except ImportError:
        return _check_with_socket(domain)


def _check_with_dnspython(domain: str) -> List[Finding]:
    import dns.resolver
    import dns.dnssec
    import dns.rdatatype

    findings = []

    # Check DNSSEC: query for DNSKEY record with DO bit
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        try:
            resolver.resolve(domain, "DNSKEY")
            # DNSKEY exists — DNSSEC is configured
            return []
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.NoNameservers:
            pass

        # Fallback: check if DS record exists in parent zone
        try:
            resolver.resolve(domain, "DS")
            return []
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass

        findings.append(_make_finding(domain))
    except Exception:
        findings.append(_make_finding(domain))

    # Check for SPF record
    findings.extend(_check_spf(domain, resolver))

    # Check for DMARC record
    findings.extend(_check_dmarc(domain, resolver))

    return findings


def _check_spf(domain: str, resolver) -> List[Finding]:
    import dns.resolver
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if txt.startswith("v=spf1"):
                return []
    except Exception:
        pass
    return [Finding(
        title="Missing SPF Record",
        severity=Severity.MEDIUM,
        url=f"dns://{domain}",
        parameter=None,
        payload=None,
        evidence=f"No SPF TXT record found for {domain}",
        description=(
            f"No SPF (Sender Policy Framework) record was found for {domain}. "
            "Without SPF, attackers can send spoofed emails appearing to originate from this domain."
        ),
        remediation="Add an SPF TXT record to your DNS zone: v=spf1 include:_spf.yourmailprovider.com ~all",
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-16",
        cvss=5.3,
        confidence=0.95,
        standards={"OWASP": "A05:2021", "CWE": "CWE-16"},
    )]


def _check_dmarc(domain: str, resolver) -> List[Finding]:
    import dns.resolver
    try:
        resolver.resolve(f"_dmarc.{domain}", "TXT")
        return []
    except Exception:
        pass
    return [Finding(
        title="Missing DMARC Record",
        severity=Severity.MEDIUM,
        url=f"dns://{domain}",
        parameter=None,
        payload=None,
        evidence=f"No DMARC TXT record found at _dmarc.{domain}",
        description=(
            f"No DMARC (Domain-based Message Authentication) policy was found for {domain}. "
            "DMARC instructs receiving mail servers how to handle emails that fail SPF/DKIM checks."
        ),
        remediation="Add a DMARC TXT record: _dmarc.yourdomain.com → v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-16",
        cvss=5.3,
        confidence=0.95,
        standards={"OWASP": "A05:2021", "CWE": "CWE-16"},
    )]


def _check_with_socket(domain: str) -> List[Finding]:
    # Minimal fallback — just flag DNSSEC without deep DNS queries
    return [_make_finding(domain)]


def _make_finding(domain: str) -> Finding:
    return Finding(
        title="DNSSEC Not Enabled",
        severity=Severity.LOW,
        url=f"dns://{domain}",
        parameter=None,
        payload=None,
        evidence=f"No DNSKEY or DS record found for {domain}",
        description=(
            f"DNSSEC (DNS Security Extensions) is not configured for {domain}. "
            "Without DNSSEC, DNS responses for this domain can be forged by an attacker on the path "
            "(DNS cache poisoning / BGP hijacking), redirecting users to malicious servers."
        ),
        remediation=(
            "Enable DNSSEC at your DNS registrar and hosting provider. "
            "Generate a KSK/ZSK key pair, sign your zone, and publish DS records to the parent zone."
        ),
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-350",
        cvss=3.7,
        confidence=0.90,
        standards={"OWASP": "A05:2021", "CWE": "CWE-350"},
    )
