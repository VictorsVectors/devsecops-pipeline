#!/usr/bin/env python3
"""
normalize-sca.py — OWASP Dependency-Check SCA Output Normalization
Project: Automated SDLC Security Scanner (DevSecOps Pipeline)
Maps to: SRQ-010 (Known Vulnerability Threshold Enforcement)

Consumes raw JSON output from OWASP Dependency-Check and normalizes it
into the same unified schema used by normalize.py (SAST normalization).

This schema consistency is critical — evaluate.py (the policy gate) reads
ALL normalized JSON files and must be able to process them identically
regardless of which tool produced them.

Normalized schema per finding (matches SAST schema exactly):
{
    "tool":        str,   # "dependency-check"
    "finding_id":  str,   # deterministic hash of tool+package+cve
    "severity":    str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "category":    str,   # "A06:2021 - Vulnerable and Outdated Components"
    "file":        str,   # package name + version e.g. "Jinja2:2.9.6"
    "line":        int,   # always 0 for SCA (no line number concept)
    "rule_id":     str,   # CVE identifier e.g. "CVE-2020-28493"
    "description": str,   # CVE description
    "cwe":         str,   # CWE identifier e.g. "CWE-79"
    "timestamp":   str,   # ISO 8601 UTC timestamp of scan
}

Dependency-Check JSON structure:
{
  "reportSchema": "...",
  "dependencies": [
    {
      "fileName": "Jinja2-2.9.6.dist-info/METADATA",
      "packages": [{"id": "pkg:pypi/jinja2@2.9.6", ...}],
      "vulnerabilities": [
        {
          "name": "CVE-2020-28493",
          "severity": "HIGH",
          "cvssv3": {"baseScore": 7.5, ...},
          "description": "...",
          "cwes": ["CWE-79"],
          ...
        }
      ]
    }
  ]
}
"""

import json
import sys
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Schema helpers (mirrors normalize.py)
# ---------------------------------------------------------------------------

def make_finding_id(tool: str, package: str, cve: str) -> str:
    """Deterministic finding ID: hash of tool + package + CVE."""
    raw = f"{tool}:{package}:{cve}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_severity_dc(severity: str, cvss_score: float = 0.0) -> str:
    """
    Map Dependency-Check severity to normalized schema.
    Dependency-Check uses: CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN
    Falls back to CVSS v3 base score if severity is UNKNOWN.
    """
    severity_upper = severity.upper() if severity else "UNKNOWN"

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "INFO":     "INFO",
        "NONE":     "INFO",
    }

    if severity_upper in mapping:
        return mapping[severity_upper]

    # Fall back to CVSS score ranges if severity is UNKNOWN
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0.0:
        return "LOW"
    return "INFO"


def extract_package_name(dependency: dict) -> str:
    """
    Extract a human-readable package name from a dependency entry.
    Prefers the packages[].id purl format, falls back to fileName.
    e.g. "pkg:pypi/jinja2@2.9.6" → "jinja2:2.9.6"
    """
    packages = dependency.get("packages", [])
    if packages:
        purl = packages[0].get("id", "")
        # purl format: pkg:pypi/jinja2@2.9.6
        if "@" in purl and "/" in purl:
            pkg_part = purl.split("/")[-1]  # "jinja2@2.9.6"
            return pkg_part.replace("@", ":")
        if purl:
            return purl

    # Fall back to fileName
    filename = dependency.get("fileName", "unknown")
    # Strip common path prefixes
    return Path(filename).name


def extract_cwe(vuln: dict) -> str:
    """Extract first CWE from vulnerability entry."""
    cwes = vuln.get("cwes", [])
    if isinstance(cwes, list) and cwes:
        return str(cwes[0])
    # Some versions use "cwe" as a string
    cwe = vuln.get("cwe", "")
    return str(cwe) if cwe else ""


# ---------------------------------------------------------------------------
# Dependency-Check parser
# ---------------------------------------------------------------------------

def parse_dependency_check(raw: dict, timestamp: str) -> list:
    """
    Parse OWASP Dependency-Check JSON output into normalized findings.
    Only processes dependencies that have at least one vulnerability.
    """
    findings = []
    dependencies = raw.get("dependencies", [])

    for dep in dependencies:
        vulnerabilities = dep.get("vulnerabilities", [])
        if not vulnerabilities:
            continue

        package_name = extract_package_name(dep)

        for vuln in vulnerabilities:
            cve = vuln.get("name", "UNKNOWN")

            # Extract CVSS score for severity fallback
            cvss_score = 0.0
            cvssv3 = vuln.get("cvssv3", {})
            if cvssv3:
                cvss_score = float(cvssv3.get("baseScore", 0.0))
            else:
                cvssv2 = vuln.get("cvssv2", {})
                if cvssv2:
                    cvss_score = float(cvssv2.get("score", 0.0))

            severity    = normalize_severity_dc(
                              vuln.get("severity", "UNKNOWN"), cvss_score)
            description = vuln.get("description", "No description available")
            cwe         = extract_cwe(vuln)

            finding = {
                "tool":        "dependency-check",
                "finding_id":  make_finding_id(
                                   "dependency-check", package_name, cve),
                "severity":    severity,
                "category":    "A06:2021 - Vulnerable and Outdated Components",
                "file":        package_name,
                "line":        0,
                "rule_id":     cve,
                "description": description.strip()[:500],  # cap at 500 chars
                "cwe":         cwe,
                "timestamp":   timestamp,
            }
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Deduplication (same logic as normalize.py)
# ---------------------------------------------------------------------------

def deduplicate(findings: list) -> list:
    seen_ids = set()
    unique = []
    for finding in findings:
        fid = finding["finding_id"]
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique.append(finding)
    return unique


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Normalize OWASP Dependency-Check JSON output to unified schema."
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to Dependency-Check JSON output file",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to write normalized JSON output (default: stdout)",
        default=None,
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    timestamp = now_iso()

    with open(input_path) as f:
        raw = json.load(f)

    findings = parse_dependency_check(raw, timestamp)
    print(f"[normalize-sca] Dependency-Check: {len(findings)} findings parsed",
          file=sys.stderr)

    before = len(findings)
    findings = deduplicate(findings)
    after = len(findings)
    print(f"[normalize-sca] Deduplication: {before} → {after} findings "
          f"({before - after} duplicates removed)", file=sys.stderr)

    output_data = {
        "schema_version": "1.0",
        "generated_at":   timestamp,
        "tool_count":     1,
        "finding_count":  len(findings),
        "findings":       findings,
    }

    output_json = json.dumps(output_data, indent=2)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output_json)
        print(f"[normalize-sca] Output written to: {output_path}",
              file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
