#!/usr/bin/env python3
"""
evaluate.py — Policy-as-Code Enforcement Gate
Project: Automated SDLC Security Scanner (DevSecOps Pipeline)
Maps to: SRQ-010 (Known Vulnerability Threshold Enforcement)
         SRQ-002 (Policy-as-Code Tamper Detection)

This is the final stage of the pipeline. It:
  1. Verifies the integrity of policy.yml via SHA-256 hash (SRQ-002)
  2. Loads all normalized JSON outputs from SAST, SCA, and container stages
  3. Aggregates and deduplicates findings across all tools
  4. Evaluates aggregated findings against policy.yml thresholds
  5. Outputs a structured pass/fail report
  6. Exits with code 0 (pass) or 1 (fail)

Exit code 1 is what actually blocks the pipeline in GitHub Actions.
A policy gate that does not exit 1 on violation is a reporting tool,
not a security control. This distinction is architectural, not cosmetic.

Usage:
  python3 pipeline/policy/evaluate.py \
    --policy pipeline/policy/policy.yml \
    --output outputs/policy-report.json
"""

import json
import sys
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


# ---------------------------------------------------------------------------
# Policy integrity verification (SRQ-002 / STRIDE P-T-001)
# ---------------------------------------------------------------------------

def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_policy_integrity(policy_path: Path, expected_hash: str | None) -> dict:
    """
    Verify policy.yml has not been tampered with since last known-good state.

    In a production environment the expected_hash would be stored in a
    separate trusted location (e.g., a GitHub Actions secret or a signed
    commit). For this project it is stored in the pipeline run environment
    and logged for audit trail purposes (SRQ-002).
    """
    actual_hash = compute_file_hash(policy_path)
    result = {
        "policy_path":   str(policy_path),
        "actual_hash":   actual_hash,
        "expected_hash": expected_hash,
        "verified":      True,
        "tamper_alert":  False,
    }

    if expected_hash and actual_hash != expected_hash:
        result["verified"]     = False
        result["tamper_alert"] = True
        print(
            f"[evaluate] ⚠️  TAMPER ALERT: policy.yml hash mismatch!\n"
            f"  Expected: {expected_hash}\n"
            f"  Actual:   {actual_hash}\n"
            f"  This may indicate unauthorized modification of the policy gate.\n"
            f"  Maps to STRIDE threat P-T-001 (Policy-as-Code Tampering).",
            file=sys.stderr
        )

    print(f"[evaluate] Policy integrity: SHA-256 = {actual_hash}",
          file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# Finding aggregation
# ---------------------------------------------------------------------------

def load_normalized_file(path: Path) -> list:
    """Load findings from a normalized JSON output file."""
    if not path.exists():
        print(f"[evaluate] Warning: input file not found: {path}",
              file=sys.stderr)
        return []

    with open(path) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    print(f"[evaluate] Loaded {len(findings)} findings from {path.name}",
          file=sys.stderr)
    return findings


def aggregate_findings(input_files: list) -> list:
    """
    Load and aggregate findings from all normalized input files.
    Applies cross-tool deduplication: same CWE + same file + same line
    across different tools = one finding (keep highest severity).
    """
    all_findings = []
    for filepath in input_files:
        findings = load_normalized_file(Path(filepath))
        all_findings.extend(findings)

    print(f"[evaluate] Total before dedup: {len(all_findings)} findings",
          file=sys.stderr)

    # Step 1: Exact deduplication by finding_id
    seen_ids = {}
    for finding in all_findings:
        fid = finding["finding_id"]
        if fid not in seen_ids:
            seen_ids[fid] = finding

    after_exact = list(seen_ids.values())

    # Step 2: Cross-tool deduplication
    # Key: (cwe, file, line) — same vulnerability location across tools
    # Keep finding with highest severity
    cross_tool_map = {}
    for finding in after_exact:
        cwe  = finding.get("cwe", "")
        file = finding.get("file", "")
        line = finding.get("line", 0)

        # Only deduplicate when CWE is known and line > 0
        # (SCA/container findings at line 0 are kept separately)
        if cwe and line > 0:
            key = (cwe, file, line)
            if key not in cross_tool_map:
                cross_tool_map[key] = finding
            else:
                # Keep highest severity
                existing_rank = SEVERITY_RANK.get(
                    cross_tool_map[key]["severity"], 99)
                new_rank = SEVERITY_RANK.get(finding["severity"], 99)
                if new_rank < existing_rank:
                    cross_tool_map[key] = finding
        else:
            # No CWE or line 0 — keep as unique
            unique_key = finding["finding_id"]
            cross_tool_map[unique_key] = finding

    deduplicated = list(cross_tool_map.values())
    removed = len(after_exact) - len(deduplicated)
    print(
        f"[evaluate] Deduplication: {len(all_findings)} → "
        f"{len(after_exact)} (exact) → "
        f"{len(deduplicated)} (cross-tool, {removed} cross-tool dupes removed)",
        file=sys.stderr
    )

    return deduplicated


# ---------------------------------------------------------------------------
# Severity counting
# ---------------------------------------------------------------------------

def count_by_severity(findings: list) -> dict:
    """Count findings by severity level."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "INFO").upper()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["INFO"] += 1
    return counts


def count_by_tool(findings: list) -> dict:
    """Count findings by tool."""
    counts = {}
    for finding in findings:
        tool = finding.get("tool", "unknown")
        counts[tool] = counts.get(tool, 0) + 1
    return counts


def count_by_category(findings: list) -> dict:
    """Count findings by OWASP category."""
    counts = {}
    for finding in findings:
        cat = finding.get("category", "Uncategorized")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------

def evaluate_thresholds(counts: dict, thresholds: dict) -> list:
    """
    Compare severity counts against policy thresholds.
    Returns list of violations.
    """
    violations = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        limit = thresholds.get(severity.lower(), 999)
        actual = counts.get(severity, 0)
        if actual > limit:
            violations.append({
                "severity": severity,
                "count":    actual,
                "limit":    limit,
                "excess":   actual - limit,
            })
    return violations


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report(
    policy: dict,
    findings: list,
    violations: list,
    integrity: dict,
    secrets_fail: bool,
    timestamp: str,
) -> dict:
    """Build the structured pass/fail policy report."""
    counts   = count_by_severity(findings)
    by_tool  = count_by_tool(findings)
    by_cat   = count_by_category(findings)

    passed = len(violations) == 0 and not secrets_fail

    # Top 10 most severe findings for the report summary
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.get("severity", "INFO"), 99),
                       f.get("file", ""))
    )
    top_findings = sorted_findings[:10]

    report = {
        "schema_version":  "1.0",
        "generated_at":    timestamp,
        "policy_version":  policy.get("policy_version", "unknown"),
        "result":          "PASS" if passed else "FAIL",
        "passed":          passed,

        "policy_integrity": integrity,

        "thresholds": policy.get("thresholds", {}),
        "severity_counts": counts,
        "violations": violations,
        "secrets_violation": secrets_fail,

        "summary": {
            "total_findings":  len(findings),
            "by_tool":         by_tool,
            "by_owasp_category": by_cat,
        },

        "top_findings": top_findings,
    }

    return report


def print_summary(report: dict) -> None:
    """Print a human-readable summary to stdout."""
    result  = report["result"]
    counts  = report["severity_counts"]
    thresh  = report["thresholds"]
    viols   = report["violations"]
    total   = report["summary"]["total_findings"]

    print("\n" + "="*70)
    print(f"  POLICY GATE RESULT: {result}")
    print("="*70)
    print(f"\n  Total findings (deduplicated): {total}")
    print(f"\n  Severity breakdown vs thresholds:")
    print(f"    CRITICAL : {counts.get('CRITICAL', 0):>5}  "
          f"(limit: {thresh.get('critical', 0)})")
    print(f"    HIGH     : {counts.get('HIGH', 0):>5}  "
          f"(limit: {thresh.get('high', 999)})")
    print(f"    MEDIUM   : {counts.get('MEDIUM', 0):>5}  "
          f"(limit: {thresh.get('medium', 999)})")
    print(f"    LOW      : {counts.get('LOW', 0):>5}  "
          f"(limit: {thresh.get('low', 999)})")
    print(f"    INFO     : {counts.get('INFO', 0):>5}")

    if report.get("secrets_violation"):
        print(f"\n  ⚠️  SECRETS VIOLATION: Trufflehog detected credentials in "
              f"git history")

    if viols:
        print(f"\n  VIOLATIONS ({len(viols)}):")
        for v in viols:
            print(f"    {v['severity']}: {v['count']} findings "
                  f"(limit {v['limit']}, excess {v['excess']})")
    else:
        print(f"\n  No threshold violations.")

    print(f"\n  Findings by tool:")
    for tool, count in report["summary"]["by_tool"].items():
        print(f"    {tool:<25} {count:>5}")

    if report["policy_integrity"]["tamper_alert"]:
        print(f"\n  ⚠️  POLICY TAMPER ALERT — See integrity section of report")

    print("="*70 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Policy-as-code enforcement gate for the DevSecOps pipeline."
    )
    parser.add_argument(
        "--policy",
        type=str,
        default="pipeline/policy/policy.yml",
        help="Path to policy.yml configuration file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/policy-report.json",
        help="Path to write the policy report JSON",
    )
    parser.add_argument(
        "--expected-hash",
        type=str,
        default=None,
        help="Expected SHA-256 hash of policy.yml for tamper detection (SRQ-002)",
    )
    args = parser.parse_args()

    timestamp   = now_iso()
    policy_path = Path(args.policy)

    # --- Load policy ---
    if not policy_path.exists():
        print(f"Error: Policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(1)

    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    # --- Verify policy integrity (SRQ-002) ---
    integrity = verify_policy_integrity(policy_path, args.expected_hash)

    # --- Aggregate findings ---
    input_files = policy.get("input_files", [])
    if not input_files:
        print("Error: No input_files defined in policy.yml", file=sys.stderr)
        sys.exit(1)

    findings = aggregate_findings(input_files)

    # --- Check for secrets ---
    # Trufflehog findings are in trufflehog-raw.json (not normalized JSON)
    # For now we check if any finding has tool=trufflehog in normalized outputs
    # Full Trufflehog integration happens when the JSON output is normalized
    secrets_fail = False
    if policy.get("fail_on_new_secrets", False):
        trufflehog_findings = [
            f for f in findings if f.get("tool") == "trufflehog"
        ]
        if trufflehog_findings:
            secrets_fail = True
            print(
                f"[evaluate] Secrets violation: "
                f"{len(trufflehog_findings)} Trufflehog findings",
                file=sys.stderr
            )

    # --- Evaluate thresholds ---
    thresholds = policy.get("thresholds", {})
    counts     = count_by_severity(findings)
    violations = evaluate_thresholds(counts, thresholds)

    # --- Build and write report ---
    report = build_report(
        policy, findings, violations, integrity, secrets_fail, timestamp
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print_summary(report)

    print(f"[evaluate] Report written to: {output_path}", file=sys.stderr)

    # --- Exit code — this is what blocks the pipeline ---
    if not report["passed"]:
        print(
            f"[evaluate] Pipeline BLOCKED — policy violations detected. "
            f"Exit code 1.",
            file=sys.stderr
        )
        sys.exit(1)
    else:
        print(
            f"[evaluate] Pipeline PASSED — all thresholds within limits. "
            f"Exit code 0.",
            file=sys.stderr
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
