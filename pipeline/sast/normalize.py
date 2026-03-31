#!/usr/bin/env python3
"""
normalize.py — SAST Output Normalization Script
Project: Automated SDLC Security Scanner (DevSecOps Pipeline)
Maps to: SRQ-006, SRQ-007, SRQ-008

Consumes raw JSON output from Semgrep and Bandit and normalizes both into
a single, consistent schema. This normalized output is the contract that
all downstream pipeline components depend on:
  - pipeline/policy/evaluate.py  (policy gate)
  - reporting/generate-report.py (report generator)

Normalized schema per finding:
{
    "tool":        str,   # "semgrep" | "bandit"
    "finding_id":  str,   # deterministic hash of tool+file+line+rule
    "severity":    str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "category":    str,   # OWASP category e.g. "A03:2021 - Injection"
    "file":        str,   # relative file path
    "line":        int,   # line number of finding
    "rule_id":     str,   # tool-specific rule/test ID
    "description": str,   # human-readable finding description
    "cwe":         str,   # CWE identifier e.g. "CWE-89"
    "timestamp":   str,   # ISO 8601 UTC timestamp of scan
}

Why normalize?
Semgrep and Bandit produce structurally different JSON. Without normalization,
the policy gate would need tool-specific parsing logic, making it fragile and
hard to extend. A single schema means adding a new tool only requires writing
a new parser function — the gate and reporter stay unchanged.
"""

import json
import sys
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def make_finding_id(tool: str, file: str, line: int, rule_id: str) -> str:
    """
    Generate a deterministic finding ID by hashing tool+file+line+rule.
    This enables deduplication across runs — the same finding in the same
    location always produces the same ID regardless of scan order.
    """
    raw = f"{tool}:{file}:{line}:{rule_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_severity_semgrep(severity: str) -> str:
    """Map Semgrep severity strings to normalized schema values."""
    mapping = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "INFO",
    }
    return mapping.get(severity.upper(), "INFO")


def normalize_severity_bandit(severity: str) -> str:
    """Map Bandit severity strings to normalized schema values."""
    mapping = {
        "HIGH":   "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW":    "LOW",
    }
    return mapping.get(severity.upper(), "LOW")


def extract_cwe(metadata: dict) -> str:
    """
    Extract CWE from Semgrep metadata. Semgrep stores CWE in metadata.cwe
    as either a string or list. Returns first CWE found or empty string.
    """
    cwe = metadata.get("cwe", "")
    if isinstance(cwe, list):
        return cwe[0] if cwe else ""
    return str(cwe)


def extract_owasp(metadata: dict) -> str:
    """
    Extract OWASP category from Semgrep metadata. Returns first entry
    if list, or string value directly.
    """
    owasp = metadata.get("owasp", "")
    if isinstance(owasp, list):
        return owasp[0] if owasp else ""
    return str(owasp)


# CWE → OWASP category lookup for Bandit findings
# Bandit doesn't output OWASP categories natively — we map from CWE
BANDIT_CWE_TO_OWASP = {
    "CWE-89":  "A03:2021 - Injection",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-259": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-20":  "A08:2021 - Software and Data Integrity Failures",
    "CWE-78":  "A03:2021 - Injection",
    "CWE-94":  "A03:2021 - Injection",
    "CWE-676": "A08:2021 - Software and Data Integrity Failures",
}


# ---------------------------------------------------------------------------
# Semgrep parser
# ---------------------------------------------------------------------------

def parse_semgrep(raw: dict, timestamp: str) -> list:
    """
    Parse Semgrep JSON output (semgrep --json) into normalized findings.

    Semgrep JSON structure:
    {
        "results": [
            {
                "check_id": "pipeline.sast.flask-sqli-string-format",
                "path": "app/app.py",
                "start": {"line": 293, ...},
                "extra": {
                    "message": "SQL Injection...",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": "CWE-89: ...",
                        "owasp": "A03:2021 - Injection",
                        ...
                    }
                }
            }
        ],
        "errors": [...]
    }
    """
    findings = []
    results = raw.get("results", [])

    for result in results:
        rule_id  = result.get("check_id", "unknown")
        filepath = result.get("path", "unknown")
        line     = result.get("start", {}).get("line", 0)
        extra    = result.get("extra", {})
        message  = extra.get("message", "No description available")
        severity = normalize_severity_semgrep(extra.get("severity", "INFO"))
        metadata = extra.get("metadata", {})
        cwe      = extract_cwe(metadata)
        category = extract_owasp(metadata)

        # Strip CWE description suffix e.g. "CWE-89: Improper..." → "CWE-89"
        cwe_short = cwe.split(":")[0].strip() if ":" in cwe else cwe

        finding = {
            "tool":        "semgrep",
            "finding_id":  make_finding_id("semgrep", filepath, line, rule_id),
            "severity":    severity,
            "category":    category,
            "file":        filepath,
            "line":        line,
            "rule_id":     rule_id,
            "description": message.strip(),
            "cwe":         cwe_short,
            "timestamp":   timestamp,
        }
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Bandit parser
# ---------------------------------------------------------------------------

def parse_bandit(raw: dict, timestamp: str) -> list:
    """
    Parse Bandit JSON output (bandit -f json) into normalized findings.

    Bandit JSON structure:
    {
        "results": [
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "filename": "app/app.py",
                "line_number": 293,
                "issue_severity": "MEDIUM",
                "issue_confidence": "LOW",
                "issue_text": "Possible SQL injection...",
                "issue_cwe": {
                    "id": 89,
                    "link": "https://cwe.mitre.org/data/definitions/89.html"
                }
            }
        ]
    }
    """
    findings = []
    results = raw.get("results", [])

    for result in results:
        rule_id    = result.get("test_id", "unknown")
        test_name  = result.get("test_name", "unknown")
        filepath   = result.get("filename", "unknown")
        line       = result.get("line_number", 0)
        severity   = normalize_severity_bandit(
                         result.get("issue_severity", "LOW"))
        description = result.get("issue_text", "No description available")

        # Extract CWE — Bandit stores as {"id": 89, "link": "..."}
        cwe_obj = result.get("issue_cwe", {})
        if isinstance(cwe_obj, dict):
            cwe = f"CWE-{cwe_obj.get('id', '')}" if cwe_obj.get("id") else ""
        else:
            cwe = str(cwe_obj)

        category = BANDIT_CWE_TO_OWASP.get(cwe, "Uncategorized")

        # Normalise filepath — Bandit sometimes outputs absolute paths
        try:
            filepath = str(Path(filepath))
        except Exception:
            pass

        finding = {
            "tool":        "bandit",
            "finding_id":  make_finding_id("bandit", filepath, line, rule_id),
            "severity":    severity,
            "category":    category,
            "file":        filepath,
            "line":        line,
            "rule_id":     f"{rule_id}:{test_name}",
            "description": description.strip(),
            "cwe":         cwe,
            "timestamp":   timestamp,
        }
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(findings: list) -> list:
    """
    Remove duplicate findings across tools using finding_id.

    Deduplication logic:
    - Same finding_id = same tool + file + line + rule → exact duplicate
    - For cross-tool deduplication (same CWE + file + line from both Semgrep
      and Bandit), we keep both findings but flag them. True cross-tool dedup
      is handled in evaluate.py at the policy gate level where severity
      aggregation occurs.

    This conservative approach avoids suppressing legitimate findings where
    two tools independently detect the same issue with different context.
    """
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
        description="Normalize Semgrep and Bandit JSON output to a unified schema."
    )
    parser.add_argument(
        "--semgrep",
        type=str,
        help="Path to Semgrep JSON output file",
        default=None,
    )
    parser.add_argument(
        "--bandit",
        type=str,
        help="Path to Bandit JSON output file",
        default=None,
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to write normalized JSON output (default: stdout)",
        default=None,
    )
    args = parser.parse_args()

    if not args.semgrep and not args.bandit:
        print("Error: at least one of --semgrep or --bandit must be provided.",
              file=sys.stderr)
        sys.exit(1)

    timestamp = now_iso()
    all_findings = []

    # Parse Semgrep output
    if args.semgrep:
        semgrep_path = Path(args.semgrep)
        if not semgrep_path.exists():
            print(f"Error: Semgrep output file not found: {semgrep_path}",
                  file=sys.stderr)
            sys.exit(1)
        with open(semgrep_path) as f:
            raw = json.load(f)
        semgrep_findings = parse_semgrep(raw, timestamp)
        print(f"[normalize] Semgrep: {len(semgrep_findings)} findings parsed",
              file=sys.stderr)
        all_findings.extend(semgrep_findings)

    # Parse Bandit output
    if args.bandit:
        bandit_path = Path(args.bandit)
        if not bandit_path.exists():
            print(f"Error: Bandit output file not found: {bandit_path}",
                  file=sys.stderr)
            sys.exit(1)
        with open(bandit_path) as f:
            raw = json.load(f)
        bandit_findings = parse_bandit(raw, timestamp)
        print(f"[normalize] Bandit: {len(bandit_findings)} findings parsed",
              file=sys.stderr)
        all_findings.extend(bandit_findings)

    # Deduplicate
    before = len(all_findings)
    all_findings = deduplicate(all_findings)
    after = len(all_findings)
    print(f"[normalize] Deduplication: {before} → {after} findings "
          f"({before - after} duplicates removed)", file=sys.stderr)

    # Output
    output_data = {
        "schema_version": "1.0",
        "generated_at":   timestamp,
        "tool_count":     sum([1 if args.semgrep else 0,
                               1 if args.bandit else 0]),
        "finding_count":  len(all_findings),
        "findings":       all_findings,
    }

    output_json = json.dumps(output_data, indent=2)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output_json)
        print(f"[normalize] Output written to: {output_path}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
