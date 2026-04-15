# Automated SDLC Security Scanner

**A fully automated DevSecOps CI/CD pipeline with OWASP Top 10 coverage, policy-as-code enforcement, and runtime SIEM detection.**

---

## Overview

This pipeline automatically detects vulnerability classes from the OWASP Top 10 on every commit, enforces configurable security thresholds at a policy gate before any deployment, and monitors a running application for the same vulnerability classes at runtime. It is built entirely on open-source tooling with zero cloud cost.

The target is an intentionally vulnerable Python 2.7 Flask application (forked from [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App)), seeded with SQL injection, pickle deserialization, hardcoded credentials, insecure dependencies, and container misconfigurations.

---

## Pipeline Architecture

```
Code Commit
    |
    +---> [Phase 1: Parallel] -------------------------+
    |         SAST: Semgrep + Bandit                   |
    |         Secrets: Trufflehog v3                   |
    |                                                   |
    +---> [Phase 2: Parallel] -------------------------+
    |         SCA: OWASP Dependency-Check               |
    |         Container: Trivy                          |
    |                                                   |
    +---> [Phase 3: Sequential] ----------------------->+
    |         DAST: OWASP ZAP (Spider + Active Scan)   |
    |                                                   |
    +---> [Policy Gate] --------------------------------+
              evaluate.py + policy.yml
              Aggregates + deduplicates all findings
              Enforces CRITICAL:0 / HIGH:5 / MEDIUM:15
              EXIT 0 = deploy | EXIT 1 = block
                   |
                   v
             [Wazuh 4.7.3 SIEM]
             Runtime detection (independent of pipeline)
             Custom rules: SQLi, brute force, pickle RCE
```

---

## Scanning Stages

| Stage | Tool(s) | What It Detects | Output |
|---|---|---|---|
| SAST | Semgrep + Bandit | Injection (CWE-89, CWE-78), deserialization (CWE-502), hardcoded credentials (CWE-798) | `Outputs/sast-normalized.json` |
| Secrets Detection | Trufflehog v3 | Live, verifiable credentials committed to the repo or history | `Outputs/secrets-normalized.json` |
| SCA | OWASP Dependency-Check | Known CVEs in Python package dependencies (NVD-backed) | `Outputs/sca-normalized.json` |
| Container Scan | Trivy | OS-level and application-level CVEs in the built Docker image | `Outputs/trivy-normalized.json` |
| DAST | OWASP ZAP | Missing security headers, XSS, authentication probes, directory traversal | `Outputs/zap-normalized.json` |
| Policy Gate | evaluate.py + policy.yml | Aggregates all stages; blocks on threshold violation or policy tampering | Exit code 0/1 |
| Runtime SIEM | Wazuh 4.7.3 | SQL injection, brute force auth, pickle deserialization RCE at runtime | Wazuh dashboard alerts |

---

## Repository Structure

```
devsecops-pipeline/
├── .github/
│   └── workflows/
│       ├── devsecops-pipeline.yml      # Phase 1 + 2 parallel jobs
│       └── dast-and-report.yml         # Phase 3 DAST + reporting
├── App/
│   ├── app.py                          # Vulnerable Flask application (annotated)
│   └── requirements.txt
├── Pipeline/
│   ├── Sast/
│   │   ├── semgrep-rules.yml           # Custom Semgrep rules
│   │   ├── bandit-config.yaml
│   │   └── normalize.py               # 10-field unified JSON schema
│   ├── Secrets/
│   │   └── trufflehog-config.yml
│   ├── Sca/
│   │   └── normalize-sca.py
│   ├── Container/
│   │   └── normalize-trivy.py
│   ├── Dast/
│   │   ├── zap-scan.py                 # ZAP orchestration (baseline + full-scan)
│   │   └── attack-mapping.json         # ZAP alerts mapped to MITRE ATT&CK
│   └── Policy/
│       ├── policy.yml                  # Severity thresholds + tamper detection
│       └── evaluate.py
├── Reporting/
│   └── generate-report.py             # HTML/PDF report generator (Jinja2 + WeasyPrint)
├── Wazuh/
│   ├── Rules/
│   │   └── custom-rules.xml           # Rules 100001-100004
│   └── Playbooks/
│       └── ir-playbook.md             # IR playbook: SQLi, brute force, pickle RCE
├── Docs/
│   ├── Threat-Model/
│   │   ├── stride-threat-model.md
│   │   ├── security-requirements.md
│   │   └── architecture.md
│   ├── Design-Report/
│   ├── Methodology-Report/
│   └── Final-Report/
│       └── Final_Technical_Report_D5.docx
├── Outputs/                            # Gitignored: sample pipeline run artifacts
├── Dockerfile
├── docker-compose.yml                  # Flask app + Wazuh stack
└── README.md
```

---

## Prerequisites

- Docker and Docker Compose (tested on Docker 24.x)
- Python 3.8+ with pip
- Node.js 18+ (for report generation dependencies)
- Git

### GitHub Secrets Required

| Secret | Purpose |
|---|---|
| `NVD_API_KEY` | OWASP Dependency-Check NVD rate limit bypass |
| `POLICY_YML_HASH` | SHA-256 of `Pipeline/Policy/policy.yml` for tamper detection |

---

## Setup and Usage

### 1. Clone the repository

```bash
git clone https://github.com/your-username/devsecops-pipeline.git
cd devsecops-pipeline
```

### 2. Start the target application

```bash
docker compose up flask-app -d
# Verify: http://localhost:5050
```

### 3. Run the full pipeline locally

```bash
# SAST
cd Pipeline/Sast
semgrep --config semgrep-rules.yml ../../App/
bandit -c bandit-config.yaml -r ../../App/ -f json -o ../../Outputs/bandit-output.json

# Normalize SAST
python normalize.py

# DAST (requires running Flask app)
cd ../Dast
python zap-scan.py --full-scan

# Generate report
cd ../../Reporting
python generate-report.py
```

### 4. Run the full pipeline via GitHub Actions

Push any commit to `main`. The workflow triggers automatically.

```bash
git add .
git commit -m "trigger pipeline run"
git push origin main
```

Monitor at: `https://github.com/your-username/devsecops-pipeline/actions`

### 5. Start the Wazuh SIEM stack

```bash
docker compose up wazuh-manager wazuh-indexer wazuh-dashboard -d
# Dashboard: https://localhost:443
# Default credentials: see Wazuh docs or your .env file
```

---

## Policy Gate Configuration

`Pipeline/Policy/policy.yml` defines the blocking thresholds:

```yaml
thresholds:
  critical: 0      # Any CRITICAL finding blocks deployment
  high: 5          # More than 5 HIGH findings blocks deployment
  medium: 15       # More than 15 MEDIUM findings blocks deployment

fail_on_new_secrets: true

policy_hash: "<SHA-256 of this file>"   # Tamper detection
```

To recalculate the hash after editing:

```bash
sha256sum Pipeline/Policy/policy.yml
# Update POLICY_YML_HASH GitHub Secret with the output
```

---

## Wazuh Detection Rules

Custom rules are defined in `Wazuh/Rules/custom-rules.xml`:

| Rule ID | Severity | Trigger | ATT&CK | STRIDE |
|---|---|---|---|---|
| 100001 | Level 10 (High) | SQL error strings in Flask logs | T1190 | A-T-001 |
| 100002 | Level 3 (Low) | Single auth failure (parent rule) | T1110 | A-S-001 |
| 100003 | Level 10 (High) | 5+ auth failures in 60 seconds | T1110 | A-S-001 |
| 100004 | Level 12 (Critical) | Pickle deserialization invoked at runtime | T1059.006 | A-T-002 |

---

## Sample Pipeline Output

```
[SAST]      17 findings (8 HIGH, 9 MEDIUM) — Semgrep + Bandit
[SECRETS]   Trufflehog: custom detector configured, verification-first
[SCA]       CVEs found in 8+ packages — OWASP Dependency-Check
[CONTAINER] 2,852 findings (CRITICAL threshold exceeded) — Trivy
[DAST]      8 deduplicated alerts — OWASP ZAP
[POLICY]    EXIT 1 — CRITICAL threshold exceeded. Deployment blocked.

[WAZUH]     Rule 100004 fired (level 12): Pickle deserialization RCE — 420+ alerts
[WAZUH]     Rule 100001 fired (level 10): SQL injection attempt — DETECTED
[WAZUH]     Rule 100003 fired (level 10): Brute force — 5 auth failures in 60s
```

---

## Deliverables Index

| Deliverable | Description | Git Tag | Document |
|---|---|---|---|
| D1 | Threat Model and Security Requirements | v0.1 | `Docs/Threat-Model/` |
| D2 | Full Pipeline + Design Report | v0.2 | `Docs/Design-Report/` |
| D3 | Report Generator + Methodology Report | v0.3 | `Docs/Methodology-Report/` |
| D4 | Wazuh SIEM Integration + IR Playbook | v0.4 | `Wazuh/Playbooks/ir-playbook.md` |
| D5 | Final Technical Report + Portfolio Polish | v1.0 | `Docs/Final-Report/` |

---

## Framework Alignment

| Framework | Alignment |
|---|---|
| OWASP Top 10 2021 | A01, A02, A03, A05, A06, A07, A08 covered |
| MITRE ATT&CK | T1190, T1059.007, T1082, T1557, T1110, T1059.006 mapped |
| CIS Controls v8 | CIS 6.1, 8.2, 8.5, 8.11, 12.1, 14.8, 16.1, 16.12, 16.13, 16.14 |
| NIST SP 800-218 (SSDF) | PW.1.1, PW.1.3, PW.4.1, PW.4.4, PW.7.2, PW.9.2, RV.1.3, RV.2.1, RV.2.2 |

---

## Key Design Decisions

**Why two SAST tools?** Semgrep enables custom YAML rules tuned to Flask-specific patterns. Bandit provides Python AST-level analysis for builtin misuse. Neither alone covers the full target vulnerability set.

**Why SHA-pin all GitHub Actions?** Third-party Actions are a supply chain attack surface. Mutable tags can be overwritten. Full commit SHA pins are immutable and map directly to STRIDE Tampering threats against the pipeline itself.

**Why CWE-based deduplication?** The same vulnerability can be detected by multiple tools. A SQL injection in `app.py` line 42 would otherwise appear as separate findings from Semgrep, Bandit, and ZAP. CWE + file + line deduplication produces an accurate finding count.

**Why Wazuh over the ELK stack?** Wazuh provides OSSEC-compatible rule syntax, a purpose-built security event schema, and a complete single-node Docker Compose deployment at zero cost. The ELK stack requires a paid license for production alerting capabilities.

---

## Final Technical Report

The complete final technical report is available at `Docs/Final-Report/Final_Technical_Report_D5.docx`. It covers architecture retrospective, tool selection rationale, full security control mapping, test results analysis, and enterprise scaling considerations.

---

## License

This project is released for portfolio and educational purposes. The target Flask application is derived from [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) and is intentionally vulnerable. Do not deploy it in any environment connected to a network you do not control.
