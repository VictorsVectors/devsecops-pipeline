# Pipeline Architecture

## End-to-End Data Flow

```
Code Commit → SAST / Secrets Detection → SCA → Container Build → Container Scan → DAST → Policy Gate → Deploy → Wazuh Runtime Monitoring
```

## Component Inventory

| Stage | Tool(s) | What It Detects | Output |
|---|---|---|---|
| Code Commit Trigger | GitHub Actions (push event) | Nothing – trigger only | Workflow initiation |
| SAST / Secrets Detection | Semgrep, Bandit, Trufflehog | Injection, hardcoded secrets, insecure patterns, git history credentials | Normalized JSON (SAST schema) |
| Software Composition Analysis | OWASP Dependency-Check | Known CVEs in Python dependencies (`app/requirements.txt`) | Normalized JSON (SCA schema) |
| Container Build + Scan | Docker + Trivy | Base image CVEs, Dockerfile misconfigurations (root user, exposed secrets) | Normalized JSON (container schema) |
| DAST | OWASP ZAP (headless daemon) | Runtime injection, auth bypass, XSS, misconfigurations | Normalized JSON (DAST schema) |
| Policy Gate | `pipeline/policy/evaluate.py` | Aggregated threshold violations across all tools | Pass/Fail + exit code 0/1 |
| Deploy | Docker Compose | Nothing – deployment only if gate passes | Running container |
| Runtime Monitoring | Wazuh (SIEM) | Behavioral anomalies: SQLi attempts, brute force, deserialization events | Wazuh alerts + dashboard |

## Component Detail

### SAST / Secrets Detection

| Component | Detail |
|---|---|
| **Tools** | Semgrep, Bandit, Trufflehog |
| **Protects Against** | Injection flaws (A03:2021), hardcoded secrets (A02:2021), insecure code patterns, credentials committed to git history |
| **Semgrep Role** | Pattern-based analysis; runs OWASP ruleset + custom rules targeting Flask vulnerability classes |
| **Bandit Role** | Python AST-aware analysis; detects insecure function calls, weak cryptography, unsafe deserialization |
| **Trufflehog Role** | Full git history credential scan; surfaces secrets even if deleted in a subsequent commit |
| **Output Destination** | `pipeline/sast/normalize.py` → normalized JSON schema |

### Software Composition Analysis (SCA)

| Component | Detail |
|---|---|
| **Tool** | OWASP Dependency-Check (Docker-run) |
| **Protects Against** | Known CVEs in third-party Python dependencies (A06:2021 – Vulnerable and Outdated Components) |
| **Input** | `app/requirements.txt` (intentionally pinned to outdated versions) |
| **Output Destination** | `pipeline/sca/normalize-sca.py` → normalized JSON schema |

### Container Build + Scan

| Component | Detail |
|---|---|
| **Tools** | Docker (build), Trivy (scan) |
| **Protects Against** | Base image CVEs, Dockerfile misconfigurations (running as root, old base image tags, exposed secrets in layers) |
| **Output Destination** | `pipeline/container/normalize-trivy.py` → normalized JSON schema |

### DAST

| Component | Detail |
|---|---|
| **Tool** | OWASP ZAP (headless daemon mode) |
| **Protects Against** | Runtime injection, authentication bypass, XSS, security misconfigurations — vulnerabilities only detectable against a running application |
| **Orchestration** | `pipeline/dast/zap-scan.py` — starts Flask app in Docker, launches ZAP daemon, runs Spider + Active Scan, exports JSON, shuts down cleanly |
| **Output Destination** | `pipeline/dast/attack-mapping.json` → MITRE ATT&CK mapping layer |

### Policy Gate

| Component | Detail |
|---|---|
| **Tool** | `pipeline/policy/evaluate.py` + `pipeline/policy/policy.yml` |
| **Protects Against** | Deployments that exceed defined risk thresholds across any scan stage |
| **Behavior** | Aggregates and deduplicates normalized findings from all upstream stages; evaluates against configurable severity thresholds; exits with code `1` on violation to block deployment |
| **Policy Thresholds** | `critical: 0` (zero tolerance), `high: 3`, `medium: 10`, `fail_on_new_secrets: true` |

### Runtime Monitoring

| Component | Detail |
|---|---|
| **Tool** | Wazuh (SIEM — manager + agent via Docker Compose) |
| **Protects Against** | Behavioral anomalies in the running application: SQLi attempts, brute force authentication attacks, insecure deserialization events |
| **Custom Rules** | `wazuh/rules/custom-rules.xml` — rules 100001 (SQLi), 100002 (brute force), 100003 (pickle deserialization) |
| **Output** | Wazuh alerts dashboard + incident response playbook triggers |

## Security Framework Alignment

| Framework | Application |
|---|---|
| **OWASP Top 10:2021** | Vulnerability classes targeted across SAST, SCA, DAST, and container scan stages |
| **STRIDE** | Applied to both pipeline infrastructure and Flask application threat surfaces |
| **MITRE ATT&CK v16.1** | ZAP findings and Wazuh rules mapped to ATT&CK technique IDs |
| **CIS Controls v8** | Each pipeline control maps to a CIS Control identifier (see `security-requirements.md`) |
| **NIST SP 800-218 (SSDF)** | Each security requirement maps to an SSDF practice identifier (see `security-requirements.md`) |
