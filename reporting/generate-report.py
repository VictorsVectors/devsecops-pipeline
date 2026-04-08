#!/usr/bin/env python3
"""
Reporting/generate-report.py
=============================================================================
Automated Security Assessment Report Generator
Project : Automated SDLC Security Scanner
Maps to : SRQ-006 through SRQ-011, D3 Deliverable
Stage   : Post-policy-gate reporting

Consumes all normalized JSON outputs from pipeline stages:
  - outputs/sast-normalized.json      (Semgrep + Bandit)
  - outputs/trufflehog-raw.json       (Trufflehog secrets)
  - outputs/sca-normalized.json       (OWASP Dependency-Check)
  - outputs/trivy-normalized.json     (Trivy container scan)
  - outputs/zap-normalized.json       (OWASP ZAP DAST)
  - outputs/policy-report.json        (Policy gate result)
  - pipeline/dast/attack-mapping.json (ATT&CK mappings)

Produces:
  - outputs/security-report.html      (rendered HTML)
  - outputs/security-report.pdf       (PDF via WeasyPrint)

Usage:
  python3 Reporting/generate-report.py
  python3 Reporting/generate-report.py --run-label "Run-2 Partial Remediation"
  python3 Reporting/generate-report.py --output-dir outputs/run-1
=============================================================================
"""

import argparse
import datetime
import json
import os
import sys

from jinja2 import Environment, FileSystemLoader
import weasyprint


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUTS_DIR     = os.path.join(REPO_ROOT, "outputs")
TEMPLATE_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
ATTACK_MAP_PATH = os.path.join(REPO_ROOT, "Pipeline", "Dast", "attack-mapping.json")

INPUT_FILES = {
    "sast":    os.path.join(OUTPUTS_DIR, "sast-normalized.json"),
    "secrets": os.path.join(OUTPUTS_DIR, "trufflehog-raw.json"),
    "sca":     os.path.join(OUTPUTS_DIR, "sca-normalized.json"),
    "trivy":   os.path.join(OUTPUTS_DIR, "trivy-normalized.json"),
    "zap":     os.path.join(OUTPUTS_DIR, "zap-normalized.json"),
    "policy":  os.path.join(OUTPUTS_DIR, "policy-report.json"),
}

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "INFO":     "#95a5a6",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(msg):
    ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Loaders — each handles its own file format quirks
# ---------------------------------------------------------------------------

def load_json(path):
    if not os.path.exists(path):
        log(f"WARNING: {path} not found — skipping.")
        return None
    with open(path) as f:
        return json.load(f)


def load_sast(path):
    """Load sast-normalized.json — flat list of findings."""
    data = load_json(path)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def load_secrets(path):
    """
    Load trufflehog-raw.json — newline-delimited JSON (one object per line).
    Normalizes to unified schema.
    """
    if not os.path.exists(path):
        log(f"WARNING: {path} not found — skipping.")
        return []
    findings = []
    with open(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                detector = obj.get("DetectorName", "trufflehog")
                raw      = obj.get("Raw", "")[:80]
                source   = obj.get("SourceMetadata", {})
                file_    = source.get("Data", {}).get("Git", {}).get("file", "git-history")
                commit   = source.get("Data", {}).get("Git", {}).get("commit", "")[:8]
                verified = obj.get("Verified", False)
                findings.append({
                    "tool":        "trufflehog",
                    "finding_id":  f"TH-{i:04d}",
                    "severity":    "CRITICAL" if verified else "HIGH",
                    "category":    "A02:2021 - Cryptographic Failures",
                    "file":        file_,
                    "line":        0,
                    "description": f"[{detector}] Secret detected"
                                   f"{' (VERIFIED LIVE)' if verified else ' (unverified)'}"
                                   f": {raw}... commit {commit}",
                    "cwe":         "CWE-798",
                    "timestamp":   datetime.datetime.utcnow().isoformat(),
                })
            except json.JSONDecodeError:
                continue
    return findings


def load_sca(path):
    """Load sca-normalized.json — may be flat list or wrapped object."""
    data = load_json(path)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def load_trivy(path):
    """Load trivy-normalized.json — wrapped with schema_version header."""
    data = load_json(path)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def load_zap(path):
    """Load zap-normalized.json — flat list."""
    data = load_json(path)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def load_policy(path):
    """Load policy-report.json."""
    data = load_json(path)
    if data is None:
        return {"status": "UNKNOWN", "summary": {}}
    return data


def load_attack_map(path):
    """Load attack-mapping.json and return dict keyed by zap_alert_name."""
    data = load_json(path)
    if data is None:
        return {}
    mapping = {}
    for entry in data.get("mappings", []):
        key = entry.get("zap_alert_name", "")
        mapping[key] = entry
    return mapping


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def dedup_key(finding):
    """
    CWE + file + line is the canonical dedup key across all tools.
    Findings with the same CWE at the same location in the same file
    are considered duplicates regardless of which tool surfaced them.
    For ZAP findings line is always 0; dedup on CWE + URL instead.
    """
    cwe  = finding.get("cwe", "CWE-0")
    file = finding.get("file", "")
    line = finding.get("line", 0)
    return f"{cwe}|{file}|{line}"


def deduplicate(findings):
    seen = {}
    deduped = []
    for f in findings:
        key = dedup_key(f)
        if key not in seen:
            seen[key] = True
            deduped.append(f)
    return deduped


# ---------------------------------------------------------------------------
# ATT&CK enrichment
# ---------------------------------------------------------------------------

def enrich_with_attack(findings, attack_map):
    """
    For ZAP findings, look up the alert name in attack_map and attach
    the ATT&CK technique ID and name to the finding dict.
    """
    for f in findings:
        if f.get("tool", "").startswith("zap"):
            # Extract alert name from description: "[METHOD] Alert Name: ..."
            desc = f.get("description", "")
            parts = desc.split("] ", 1)
            if len(parts) == 2:
                alert_name = parts[1].split(":")[0].strip()
                match = attack_map.get(alert_name, {})
                f["attack_technique_id"]   = match.get("attack_technique_id", "")
                f["attack_technique_name"] = match.get("attack_technique_name", "")
                f["attack_tactic"]         = match.get("attack_tactic", "")
            else:
                f["attack_technique_id"]   = ""
                f["attack_technique_name"] = ""
                f["attack_tactic"]         = ""
        else:
            f["attack_technique_id"]   = ""
            f["attack_technique_name"] = ""
            f["attack_tactic"]         = ""
    return findings


# ---------------------------------------------------------------------------
# Aggregation + summary stats
# ---------------------------------------------------------------------------

def build_severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_tool_summary(all_findings):
    summary = {}
    for f in all_findings:
        tool = f.get("tool", "unknown")
        if tool not in summary:
            summary[tool] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
        sev = f.get("severity", "INFO").upper()
        summary[tool][sev] = summary[tool].get(sev, 0) + 1
        summary[tool]["total"] += 1
    return summary


def pipeline_health_score(severity_counts, policy_status):
    """
    Simple 0-100 scorecard:
    Start at 100, deduct per severity band, floor at 0.
    Policy gate failure is an automatic cap at 40.
    """
    score = 100
    score -= severity_counts.get("CRITICAL", 0) * 20
    score -= severity_counts.get("HIGH", 0) * 5
    score -= severity_counts.get("MEDIUM", 0) * 1
    score = max(0, score)
    if policy_status not in ("PASS", "pass"):
        score = min(score, 40)
    return score


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_report(context, output_dir):
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
    )
    env.filters["severity_color"] = lambda s: SEVERITY_COLORS.get(s.upper(), "#95a5a6")

    template = env.get_template("report.html.j2")
    html_content = template.render(**context)

    html_path = os.path.join(output_dir, "security-report.html")
    pdf_path  = os.path.join(output_dir, "security-report.pdf")

    with open(html_path, "w") as f:
        f.write(html_content)
    log(f"HTML report written to {html_path}")

    log("Converting HTML to PDF via WeasyPrint...")
    weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
    log(f"PDF report written to {pdf_path}")

    return html_path, pdf_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DevSecOps Security Report Generator")
    parser.add_argument("--run-label",  default="Baseline Run",
                        help="Label for this pipeline run (e.g. 'Run-2 Partial Remediation')")
    parser.add_argument("--output-dir", default=OUTPUTS_DIR,
                        help="Directory to write report files")
    parser.add_argument("--inputs-dir", default=OUTPUTS_DIR,
                        help="Directory containing normalized JSON inputs")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Override input paths if inputs-dir specified
    input_files = {k: v.replace(OUTPUTS_DIR, args.inputs_dir) for k, v in INPUT_FILES.items()}

    log(f"=== Security Report Generator ===")
    log(f"Run label  : {args.run_label}")
    log(f"Inputs dir : {args.inputs_dir}")
    log(f"Output dir : {args.output_dir}")

    # Load all sources
    log("Loading normalized findings...")
    sast_findings    = load_sast(input_files["sast"])
    secrets_findings = load_secrets(input_files["secrets"])
    sca_findings     = load_sca(input_files["sca"])
    trivy_findings   = load_trivy(input_files["trivy"])
    zap_findings     = load_zap(input_files["zap"])
    policy_data      = load_policy(input_files["policy"])
    attack_map       = load_attack_map(ATTACK_MAP_PATH)

    log(f"Raw counts — SAST: {len(sast_findings)}, Secrets: {len(secrets_findings)}, "
        f"SCA: {len(sca_findings)}, Trivy: {len(trivy_findings)}, ZAP: {len(zap_findings)}")

    # Combine and deduplicate
    all_findings = (sast_findings + secrets_findings + sca_findings +
                    trivy_findings + zap_findings)
    all_findings = deduplicate(all_findings)
    all_findings = enrich_with_attack(all_findings, attack_map)

    # Sort by severity
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 99))

    log(f"Deduplicated total: {len(all_findings)} findings")

    # Stats
    severity_counts = build_severity_counts(all_findings)
    tool_summary    = build_tool_summary(all_findings)
    policy_status   = policy_data.get("status", "UNKNOWN")
    health_score    = pipeline_health_score(severity_counts, policy_status)

    log(f"Severity counts: {severity_counts}")
    log(f"Policy status  : {policy_status}")
    log(f"Health score   : {health_score}/100")

    # Build ZAP-only subset for ATT&CK table
    zap_with_attack = [f for f in all_findings
                       if f.get("tool", "").startswith("zap")
                       and f.get("attack_technique_id")]

    # Template context
    context = {
        "run_label":        args.run_label,
        "generated_at":     datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "all_findings":     all_findings,
        "zap_with_attack":  zap_with_attack,
        "severity_counts":  severity_counts,
        "tool_summary":     tool_summary,
        "policy_status":    policy_status,
        "policy_data":      policy_data,
        "health_score":     health_score,
        "severity_colors":  SEVERITY_COLORS,
        "total_findings":   len(all_findings),
        "raw_counts": {
            "sast":    len(sast_findings),
            "secrets": len(secrets_findings),
            "sca":     len(sca_findings),
            "trivy":   len(trivy_findings),
            "zap":     len(zap_findings),
        },
    }

    html_path, pdf_path = render_report(context, args.output_dir)

    log("=== Report generation complete ===")
    log(f"HTML : {html_path}")
    log(f"PDF  : {pdf_path}")


if __name__ == "__main__":
    main()
