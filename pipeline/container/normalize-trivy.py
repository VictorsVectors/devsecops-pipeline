#!/usr/bin/env python3
"""
normalize-trivy.py — Trivy Container Image Scan Output Normalization
Project: Automated SDLC Security Scanner (DevSecOps Pipeline)
Maps to: SRQ-009 (Container Non-Root Execution), SRQ-010 (Known Vulnerability
         Threshold Enforcement)

Consumes raw JSON output from Trivy image scan and normalizes it into the
same unified schema used by normalize.py and normalize-sca.py.

Two finding classes from Trivy are normalized:
  1. Vulnerabilities — CVEs in OS packages and application dependencies
     within the container image (Class: os-pkgs, lang-pkgs)
  2. Misconfigurations — Dockerfile/image config issues such as running
     as root, no USER instruction, exposed secrets in layers
     (Class: config)

Normalized schema per finding (matches SAST and SCA schemas):
{
    "tool":        str,   # "trivy"
    "finding_id":  str,   # deterministic hash of tool+target+vuln_id
    "severity":    str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "category":    str,   # OWASP category
    "file":        str,   # image name + target e.g. "devsecops-app:latest"
    "line":        int,   # always 0 (no line number for container findings)
    "rule_id":     str,   # CVE ID or misconfig check ID
    "description": str,   # vulnerability or misconfig description
    "cwe":         str,   # CWE if available
    "timestamp":   str,   # ISO 8601 UTC timestamp of scan
}

Trivy JSON structure (trivy image --format json):
{
  "SchemaVersion": 2,
  "ArtifactName": "devsecops-app:latest",
  "Results": [
    {
      "Target": "devsecops-app:latest (debian 9.x)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-XXXX",
          "PkgName": "libc6",
          "InstalledVersion": "2.24-11",
          "Severity": "HIGH",
          "Description": "...",
          "CweIDs": ["CWE-125"],
          ...
        }
      ]
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "Image user should not be 'root'",
          "Severity": "HIGH",
          "Description": "...",
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
# Schema helpers
# ---------------------------------------------------------------------------

def make_finding_id(tool: str, target: str, vuln_id: str) -> str:
    """Deterministic finding ID: hash of tool + target + vuln_id."""
    raw = f"{tool}:{target}:{vuln_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(severity: str) -> str:
    """Map Trivy severity strings to normalized schema values."""
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "INFO":     "INFO",
        "UNKNOWN":  "INFO",
        "NONE":     "INFO",
    }
    return mapping.get(severity.upper() if severity else "UNKNOWN", "INFO")


def vuln_to_owasp(class_type: str) -> str:
    """Map Trivy result class to OWASP category."""
    if class_type == "config":
        return "A05:2021 - Security Misconfiguration"
    return "A06:2021 - Vulnerable and Outdated Components"


def extract_cwe(vuln: dict) -> str:
    """Extract first CWE from Trivy vulnerability entry."""
    cwes = vuln.get("CweIDs", [])
    if isinstance(cwes, list) and cwes:
        return str(cwes[0])
    return ""


# ---------------------------------------------------------------------------
# Trivy parser
# ---------------------------------------------------------------------------

def parse_trivy(raw: dict, timestamp: str) -> list:
    """
    Parse Trivy JSON output into normalized findings.
    Processes both vulnerability and misconfiguration finding classes.
    """
    findings = []
    artifact_name = raw.get("ArtifactName", "unknown-image")
    results = raw.get("Results", [])

    for result in results:
        target     = result.get("Target", artifact_name)
        class_type = result.get("Class", "unknown")
        file_ref   = f"{artifact_name} → {target}"

        # --- Vulnerabilities (os-pkgs, lang-pkgs) ---
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            vuln_id     = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg_name    = vuln.get("PkgName", "unknown")
            installed   = vuln.get("InstalledVersion", "")
            fixed       = vuln.get("FixedVersion", "")
            severity    = normalize_severity(vuln.get("Severity", "UNKNOWN"))
            description = vuln.get("Description", "No description available")
            cwe         = extract_cwe(vuln)

            # Build a descriptive file reference
            pkg_ref = f"{pkg_name}:{installed}" if installed else pkg_name
            if fixed:
                description = f"{description[:300]} | FixedIn: {fixed}"

            finding = {
                "tool":        "trivy",
                "finding_id":  make_finding_id("trivy", pkg_ref, vuln_id),
                "severity":    severity,
                "category":    vuln_to_owasp(class_type),
                "file":        f"{artifact_name} | {pkg_ref}",
                "line":        0,
                "rule_id":     vuln_id,
                "description": description.strip()[:500],
                "cwe":         cwe,
                "timestamp":   timestamp,
            }
            findings.append(finding)

        # --- Misconfigurations (config class) ---
        misconfigs = result.get("Misconfigurations") or []
        for misconfig in misconfigs:
            check_id    = misconfig.get("ID", "UNKNOWN")
            title       = misconfig.get("Title", "Unknown misconfiguration")
            severity    = normalize_severity(
                              misconfig.get("Severity", "UNKNOWN"))
            description = misconfig.get("Description", "")
            message     = misconfig.get("Message", "")
            resolution  = misconfig.get("Resolution", "")

            # Combine available text fields into a useful description
            full_desc = title
            if description:
                full_desc += f". {description}"
            if message:
                full_desc += f" | {message}"
            if resolution:
                full_desc += f" | Resolution: {resolution}"

            finding = {
                "tool":        "trivy",
                "finding_id":  make_finding_id(
                                   "trivy", target, check_id),
                "severity":    severity,
                "category":    "A05:2021 - Security Misconfiguration",
                "file":        f"{artifact_name} | {target}",
                "line":        0,
                "rule_id":     check_id,
                "description": full_desc.strip()[:500],
                "cwe":         "",
                "timestamp":   timestamp,
            }
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Deduplication
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
        description="Normalize Trivy container image scan JSON to unified schema."
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to Trivy JSON output file (trivy image --format json)",
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

    findings = parse_trivy(raw, timestamp)

    vuln_count    = sum(1 for f in findings
                        if f["category"] != "A05:2021 - Security Misconfiguration"
                        or f["rule_id"].startswith("CVE"))
    misconfig_count = sum(1 for f in findings
                          if f["category"] == "A05:2021 - Security Misconfiguration"
                          and not f["rule_id"].startswith("CVE"))

    print(f"[normalize-trivy] Vulnerabilities: {vuln_count} findings",
          file=sys.stderr)
    print(f"[normalize-trivy] Misconfigurations: {misconfig_count} findings",
          file=sys.stderr)

    before = len(findings)
    findings = deduplicate(findings)
    after = len(findings)
    print(f"[normalize-trivy] Deduplication: {before} → {after} findings "
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
        print(f"[normalize-trivy] Output written to: {output_path}",
              file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
