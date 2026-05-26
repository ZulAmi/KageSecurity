from scanner.core.scan_result import ScanResult, ComplianceReport
from scanner.compliance import iso27001, hipaa, gdpr, appi

STANDARDS = {
    "iso27001": iso27001.evaluate,
    "hipaa": hipaa.evaluate,
    "gdpr": gdpr.evaluate,
    "appi": appi.evaluate,
}


def map_to_standards(scan_result: ScanResult, standards: list[str] | None = None) -> list[ComplianceReport]:
    targets = standards or list(STANDARDS.keys())
    reports = []
    for standard in targets:
        fn = STANDARDS.get(standard.lower())
        if fn:
            reports.append(fn(scan_result))
    return reports
