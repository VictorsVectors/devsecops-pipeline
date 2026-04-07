#!/usr/bin/env python3
"""
Pipeline/Dast/zap-scan.py
=============================================================================
OWASP ZAP DAST Orchestration Script
Project : Automated SDLC Security Scanner
Maps to : SRQ-011 (DAST Active Scan Coverage), OWASP A03/A07
Stage   : Phase 3 — Dynamic Application Security Testing

Execution flow
--------------
Phase A  Baseline scan  (default, fast ~5 min)
         zap-baseline.py validates ZAP can reach the app and surfaces
         passive findings. Zero false-positive risk — no attacks sent.

Phase B  Full scan      (activated by --full-scan flag, ~20-30 min)
         Spider + Active Scan via ZAP REST API. Sends actual attack
         payloads. Only run after baseline confirms app is reachable.

Output
------
outputs/zap-baseline-raw.json   — raw ZAP baseline report
outputs/zap-raw.json            — raw ZAP full scan report (if --full-scan)
outputs/zap-normalized.json     — unified 10-field schema for policy gate

Usage
-----
# Baseline only (start here):
python3 Pipeline/Dast/zap-scan.py

# Graduate to full Spider + Active Scan:
python3 Pipeline/Dast/zap-scan.py --full-scan

# Target a different host (e.g. in GitHub Actions):
python3 Pipeline/Dast/zap-scan.py --target http://localhost:5050 --full-scan
=============================================================================
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time

import requests

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_TARGET      = "http://localhost:5050"
ZAP_PORT            = 8090
ZAP_API_KEY         = "devsecops-zap-key"          # passed to ZAP daemon
ZAP_IMAGE           = "ghcr.io/zaproxy/zaproxy:stable"
OUTPUT_DIR          = "outputs"
BASELINE_OUT_JSON   = os.path.join(OUTPUT_DIR, "zap-baseline-raw.json")
FULLSCAN_OUT_JSON   = os.path.join(OUTPUT_DIR, "zap-raw.json")
NORMALIZED_OUT      = os.path.join(OUTPUT_DIR, "zap-normalized.json")

# ZAP REST API base — used only in full-scan mode
ZAP_API_BASE        = f"http://localhost:{ZAP_PORT}"
ZAP_READY_TIMEOUT   = 90    # seconds to wait for ZAP daemon to be ready
SPIDER_TIMEOUT      = 300   # seconds before spider poll gives up
ASCAN_TIMEOUT       = 1200  # seconds before active scan poll gives up


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def zap_api(path: str, params: dict = None) -> dict:
    """GET a ZAP REST API endpoint and return parsed JSON."""
    url = f"{ZAP_API_BASE}{path}"
    if params is None:
        params = {}
    params["apikey"] = ZAP_API_KEY
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Phase A — Baseline scan (passive, docker run, built-in wrapper)
# ---------------------------------------------------------------------------

def run_baseline(target: str) -> bool:
    """
    Run zap-baseline.py inside the ZAP container.
    This is ZAP's built-in passive-only scanner — no attack traffic.
    Returns True on success (findings are expected and not an error).
    """
    log("=== PHASE A: ZAP Baseline Scan ===")
    log(f"Target : {target}")
    log(f"Output : {BASELINE_OUT_JSON}")

    cmd = [
        "docker", "run", "--rm",
        "--network", "host",                         # reach localhost:5050
        "-v", f"{os.path.abspath(OUTPUT_DIR)}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t", target,
        "-J", "zap-baseline-raw.json",               # written to /zap/wrk/
        "-I",                                         # don't fail on warnings
        "--auto",
    ]

    log(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)

    # zap-baseline.py exits 1 when it finds issues — that is expected
    if result.returncode not in (0, 1, 2):
        log(f"ERROR: ZAP baseline exited with unexpected code {result.returncode}")
        return False

    if os.path.exists(BASELINE_OUT_JSON):
        log(f"Baseline complete. Report written to {BASELINE_OUT_JSON}")
        return True
    else:
        log("WARNING: Baseline JSON not found — ZAP may not have written output.")
        return False


# ---------------------------------------------------------------------------
# Phase B — Full scan (Spider + Active Scan via REST API)
# ---------------------------------------------------------------------------

def wait_for_zap() -> bool:
    """Poll ZAP's /JSON/core/view/version/ until it responds or times out."""
    log(f"Waiting for ZAP daemon on port {ZAP_PORT} (timeout {ZAP_READY_TIMEOUT}s)...")
    deadline = time.time() + ZAP_READY_TIMEOUT
    while time.time() < deadline:
        try:
            zap_api("/JSON/core/view/version/")
            log("ZAP daemon is ready.")
            return True
        except Exception:
            time.sleep(3)
    log("ERROR: ZAP daemon did not become ready in time.")
    return False


def start_zap_daemon() -> subprocess.Popen:
    """Launch ZAP in daemon mode via docker run, return the Popen handle."""
    log(f"Starting ZAP daemon (port {ZAP_PORT})...")
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{os.path.abspath(OUTPUT_DIR)}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap.sh",
        "-daemon",
        "-host", "0.0.0.0",
        "-port", str(ZAP_PORT),
        "-config", f"api.key={ZAP_API_KEY}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
        "-config", "spider.maxDuration=5",           # cap spider at 5 min
    ]
    log(f"Running: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc


def run_spider(target: str) -> str:
    """Start spider scan, poll until done, return scan ID."""
    log(f"Starting Spider against {target}...")
    resp = zap_api("/JSON/spider/action/scan/", {"url": target, "recurse": "true"})
    scan_id = resp.get("scan", "0")
    log(f"Spider scan ID: {scan_id}")

    deadline = time.time() + SPIDER_TIMEOUT
    while time.time() < deadline:
        progress = zap_api("/JSON/spider/view/status/", {"scanId": scan_id})
        pct = int(progress.get("status", 0))
        log(f"Spider progress: {pct}%")
        if pct >= 100:
            log("Spider complete.")
            return scan_id
        time.sleep(10)

    log("WARNING: Spider timed out.")
    return scan_id


def run_active_scan(target: str) -> str:
    """Start active scan, poll until done, return scan ID."""
    log(f"Starting Active Scan against {target}...")
    resp = zap_api("/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": "true",
        "inScopeOnly": "false",
    })
    scan_id = resp.get("scan", "0")
    log(f"Active scan ID: {scan_id}")

    deadline = time.time() + ASCAN_TIMEOUT
    while time.time() < deadline:
        progress = zap_api("/JSON/ascan/view/status/", {"scanId": scan_id})
        pct = int(progress.get("status", 0))
        log(f"Active scan progress: {pct}%")
        if pct >= 100:
            log("Active scan complete.")
            return scan_id
        time.sleep(15)

    log("WARNING: Active scan timed out.")
    return scan_id


def export_full_results() -> bool:
    """Export all ZAP alerts as JSON to FULLSCAN_OUT_JSON."""
    log(f"Exporting full scan results to {FULLSCAN_OUT_JSON}...")
    try:
        alerts = zap_api("/JSON/core/view/alerts/", {"baseurl": "", "start": "0", "count": "9999"})
        with open(FULLSCAN_OUT_JSON, "w") as f:
            json.dump(alerts, f, indent=2)
        log(f"Exported {len(alerts.get('alerts', []))} alerts.")
        return True
    except Exception as e:
        log(f"ERROR exporting results: {e}")
        return False


def shutdown_zap(proc: subprocess.Popen) -> None:
    """Ask ZAP to shut down gracefully, then terminate the container."""
    log("Shutting down ZAP daemon...")
    try:
        zap_api("/JSON/core/action/shutdown/")
        time.sleep(5)
    except Exception:
        pass
    if proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=15)
    log("ZAP daemon stopped.")


def run_full_scan(target: str) -> bool:
    """Orchestrate ZAP daemon + Spider + Active Scan."""
    log("=== PHASE B: ZAP Full Scan (Spider + Active Scan) ===")
    proc = start_zap_daemon()

    try:
        if not wait_for_zap():
            return False

        run_spider(target)
        run_active_scan(target)
        success = export_full_results()
        return success

    finally:
        shutdown_zap(proc)


# ---------------------------------------------------------------------------
# Normalization — baseline JSON → unified 10-field schema
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Informational": "INFO",
    "False Positive": "INFO",
}

CWE_MAP = {
    # ZAP alert names → CWE IDs (extend as your app triggers more alerts)
    "SQL Injection":                          "CWE-89",
    "Cross Site Scripting (Reflected)":       "CWE-79",
    "Cross Site Scripting (Persistent)":      "CWE-79",
    "Path Traversal":                         "CWE-22",
    "Remote OS Command Injection":            "CWE-78",
    "External Redirect":                      "CWE-601",
    "Insecure HTTP Method":                   "CWE-650",
    "Absence of Anti-CSRF Tokens":            "CWE-352",
    "Application Error Disclosure":           "CWE-209",
    "Cookie Without Secure Flag":             "CWE-614",
    "Cookie Without HttpOnly Flag":           "CWE-1004",
    "X-Content-Type-Options Header Missing":  "CWE-693",
    "X-Frame-Options Header Not Set":         "CWE-1021",
    "Information Disclosure - Debug Error Messages": "CWE-209",
    "Weak Authentication Method":             "CWE-287",
}


def normalize_baseline(raw_path: str, out_path: str) -> int:
    """
    Parse zap-baseline-raw.json (ZAP's -J output format) and emit
    the unified 10-field normalized schema used by evaluate.py.
    Returns count of findings written.
    """
    if not os.path.exists(raw_path):
        log(f"WARNING: Raw file not found: {raw_path} — skipping normalization.")
        return 0

    with open(raw_path) as f:
        raw = json.load(f)

    findings = []
    seen = set()                                     # deduplicate by alert+url

    # Baseline -J format: { "site": [ { "alerts": [...] } ] }
    sites = raw.get("site", [])
    for site in sites:
        for alert in site.get("alerts", []):
            alert_name = alert.get("name", "Unknown")
            severity   = SEVERITY_MAP.get(alert.get("riskdesc", "").split()[0], "INFO")
            cwe_raw    = alert.get("cweid", "0")
            cwe        = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "0" \
                         else CWE_MAP.get(alert_name, "CWE-0")

            for instance in alert.get("instances", [{"uri": alert.get("url", ""), "method": "GET"}]):
                uri    = instance.get("uri", "")
                method = instance.get("method", "GET")
                dedup_key = f"{alert_name}|{uri}"

                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append({
                    "tool":        "zap-baseline",
                    "finding_id":  f"ZAP-{abs(hash(dedup_key)) % 100000:05d}",
                    "severity":    severity,
                    "category":    alert.get("tags", {}).get("OWASP_2021_A", alert_name),
                    "file":        uri,
                    "line":        0,
                    "description": f"[{method}] {alert_name}: {alert.get('desc', '')}",
                    "cwe":         cwe,
                    "timestamp":   datetime.datetime.utcnow().isoformat(),
                    "raw_output":  {
                        "solution":   alert.get("solution", ""),
                        "reference":  alert.get("reference", ""),
                        "confidence": alert.get("confidence", ""),
                    }
                })

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    log(f"Normalized {len(findings)} ZAP findings → {out_path}")
    return len(findings)


def normalize_fullscan(raw_path: str, out_path: str) -> int:
    """
    Parse the full scan alerts export (zap-raw.json) and emit
    the unified normalized schema.
    """
    if not os.path.exists(raw_path):
        log(f"WARNING: Raw file not found: {raw_path} — skipping normalization.")
        return 0

    with open(raw_path) as f:
        raw = json.load(f)

    findings = []
    seen = set()

    for alert in raw.get("alerts", []):
        alert_name = alert.get("alert", "Unknown")
        severity   = SEVERITY_MAP.get(alert.get("risk", ""), "INFO")
        cwe_raw    = alert.get("cweid", "0")
        cwe        = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "0" \
                     else CWE_MAP.get(alert_name, "CWE-0")
        uri        = alert.get("url", "")
        method     = alert.get("method", "GET")
        dedup_key  = f"{alert_name}|{uri}"

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append({
            "tool":        "zap-fullscan",
            "finding_id":  f"ZAP-{abs(hash(dedup_key)) % 100000:05d}",
            "severity":    severity,
            "category":    alert.get("tags", {}).get("OWASP_2021_A", alert_name),
            "file":        uri,
            "line":        0,
            "description": f"[{method}] {alert_name}: {alert.get('desc', '')}",
            "cwe":         cwe,
            "timestamp":   datetime.datetime.utcnow().isoformat(),
            "raw_output":  {
                "solution":   alert.get("solution", ""),
                "reference":  alert.get("reference", ""),
                "confidence": alert.get("confidence", ""),
            }
        })

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    log(f"Normalized {len(findings)} ZAP findings → {out_path}")
    return len(findings)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ZAP DAST orchestration script")
    parser.add_argument("--target",    default=DEFAULT_TARGET,
                        help="Target URL (default: http://localhost:5050)")
    parser.add_argument("--full-scan", action="store_true",
                        help="Run Spider + Active Scan after baseline")
    args = parser.parse_args()

    ensure_output_dir()

    # ---- Phase A: always run baseline first --------------------------------
    baseline_ok = run_baseline(args.target)
    if not baseline_ok:
        log("Baseline scan failed — check that the Flask app is running on "
            f"{args.target} and Docker can reach it.")
        sys.exit(1)

    # Normalize baseline output immediately
    normalize_baseline(BASELINE_OUT_JSON, NORMALIZED_OUT)

    # ---- Phase B: full scan (opt-in) ---------------------------------------
    if args.full_scan:
        full_ok = run_full_scan(args.target)
        if full_ok:
            # Full scan output overwrites normalized with richer data
            normalize_fullscan(FULLSCAN_OUT_JSON, NORMALIZED_OUT)
        else:
            log("Full scan failed or timed out — baseline normalized output retained.")
            sys.exit(1)

    log("=== ZAP scan complete ===")
    log(f"Normalized output : {NORMALIZED_OUT}")


if __name__ == "__main__":
    main()
