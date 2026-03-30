# STRIDE Threat Model

## Methodology

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) was applied to two attack surfaces independently:

- **Surface 1 – CI/CD Pipeline Infrastructure:** The pipeline itself is a security-critical system. A compromised CI environment represents a supply chain attack vector capable of injecting malicious code into production artifacts at scale. Most practitioners threat-model only the application; treating the pipeline as an equal threat surface reflects real-world supply chain attack patterns (SolarWinds, 3CX).
- **Surface 2 – Target Flask Application:** The intentionally vulnerable web application serves as the primary scan target, embodying OWASP Top 10 vulnerability classes.

### Severity Ratings

| Rating | Criteria |
|---|---|
| **CRITICAL** | Direct code execution, supply chain compromise, or credential exposure with immediate impact |
| **HIGH** | Significant confidentiality, integrity, or availability impact requiring prompt remediation |
| **MEDIUM** | Moderate impact; exploitable under specific conditions or requiring chained attacks |

---

## Surface 1: CI/CD Pipeline Infrastructure

### Summary

| Threat ID | Category | Severity | Affected Component |
|---|---|---|---|
| P-S-001 | Spoofing | HIGH | GitHub Actions Runner / Workflow YAML |
| P-T-001 | Tampering | CRITICAL | Policy-as-Code Gate (`policy.yml`) |
| P-T-002 | Tampering | HIGH | Pipeline Dependencies (`requirements.txt`, pip) |
| P-R-001 | Repudiation | MEDIUM | Git History / Audit Log |
| P-I-001 | Information Disclosure | MEDIUM | GitHub Actions Logs |
| P-I-002 | Information Disclosure | HIGH | GitHub Actions Secrets Store |
| P-D-001 | Denial of Service | MEDIUM | OWASP ZAP / GitHub Actions Runners |
| P-E-001 | Elevation of Privilege | CRITICAL | GitHub Actions `GITHUB_TOKEN` |

---

### P-S-001 — Spoofing | HIGH

| Field | Detail |
|---|---|
| **Category** | Spoofing |
| **Surface** | CI/CD Pipeline |
| **Severity** | HIGH |
| **Affected Component** | GitHub Actions Runner / Workflow YAML |
| **Attack Scenario** | Attacker injects a malicious GitHub Actions workflow via a forked PR, impersonating a legitimate contributor to execute arbitrary commands within the CI runner. |
| **MITRE ATT&CK** | T1195.001 – Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| **Mitigation** | Enforce required PR reviews from CODEOWNERS; pin Actions to full commit SHA hashes (not mutable tags); restrict workflow permissions to `read-only` by default; enable branch protection rules on `main`. |

---

### P-T-001 — Tampering | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Tampering |
| **Surface** | CI/CD Pipeline |
| **Severity** | CRITICAL |
| **Affected Component** | Policy-as-Code Gate (`pipeline/policy/policy.yml`) |
| **Attack Scenario** | Attacker with write access to the repo modifies `pipeline/policy/policy.yml` to raise severity thresholds to permissive levels, disabling the enforcement gate silently. |
| **MITRE ATT&CK** | T1553 – Subvert Trust Controls |
| **Mitigation** | Protect policy files via CODEOWNERS with mandatory review. Track policy file hash in each pipeline run and alert on deviation. Commit signing (GPG) on all policy changes. |

---

### P-T-002 — Tampering | HIGH

| Field | Detail |
|---|---|
| **Category** | Tampering |
| **Surface** | CI/CD Pipeline |
| **Severity** | HIGH |
| **Affected Component** | Pipeline Dependencies (`requirements.txt`, pip) |
| **Attack Scenario** | Supply chain attack: a compromised PyPI package version is injected into the SAST tool dependency chain, causing `normalize.py` to suppress findings before reporting. |
| **MITRE ATT&CK** | T1195.002 – Supply Chain Compromise: Compromise Software Supply Chain |
| **Mitigation** | Pin all pipeline tool versions to exact SHAs. Run Dependency-Check against the pipeline's own dependencies. Use a private PyPI mirror or hash verification in CI. |

---

### P-R-001 — Repudiation | MEDIUM

| Field | Detail |
|---|---|
| **Category** | Repudiation |
| **Surface** | CI/CD Pipeline |
| **Severity** | MEDIUM |
| **Affected Component** | Git History / Audit Log |
| **Attack Scenario** | Developer force-pushes to `main`, overwriting commit history containing a prior secret exposure, eliminating the audit trail of the original offense. |
| **MITRE ATT&CK** | T1070.004 – Indicator Removal: File Deletion |
| **Mitigation** | Disable force-push on `main` and all protected branches. Enable GitHub audit log streaming. Require Trufflehog git-history scan on every pipeline run to surface retroactive exposures. |

---

### P-I-001 — Information Disclosure | MEDIUM

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Surface** | CI/CD Pipeline |
| **Severity** | MEDIUM |
| **Affected Component** | GitHub Actions Logs |
| **Attack Scenario** | Pipeline logs containing full Trivy or Bandit JSON output are exposed in public GitHub Actions run logs, revealing internal file paths, dependency versions, and vulnerability details to any observer. |
| **MITRE ATT&CK** | T1552.004 – Unsecured Credentials: Private Keys |
| **Mitigation** | Configure Actions to mask sensitive outputs with `::add-mask::`. Upload scan artifacts as encrypted workflow artifacts rather than logging raw JSON. Restrict Actions log visibility on public repos. |

---

### P-I-002 — Information Disclosure | HIGH

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Surface** | CI/CD Pipeline |
| **Severity** | HIGH |
| **Affected Component** | GitHub Actions Secrets Store |
| **Attack Scenario** | GitHub Actions secrets (e.g., `DOCKER_TOKEN`, `AWS_ACCESS_KEY`) are inadvertently echoed to step output by a misconfigured workflow step or third-party Action. |
| **MITRE ATT&CK** | T1552.001 – Unsecured Credentials: Credentials in Files |
| **Mitigation** | Use OIDC for cloud authentication instead of long-lived secrets. Audit every third-party Action for secret logging behavior. Enforce Trufflehog scan on workflow YAML files themselves. |

---

### P-D-001 — Denial of Service | MEDIUM

| Field | Detail |
|---|---|
| **Category** | Denial of Service |
| **Surface** | CI/CD Pipeline |
| **Severity** | MEDIUM |
| **Affected Component** | OWASP ZAP / GitHub Actions Runners |
| **Attack Scenario** | Attacker submits a crafted commit triggering a runaway OWASP ZAP active scan loop, consuming all GitHub Actions concurrent runner minutes and blocking legitimate deployments. |
| **MITRE ATT&CK** | T1499 – Endpoint Denial of Service |
| **Mitigation** | Set ZAP scan timeout limits (`--config spider.maxDuration=5`). Configure workflow-level `timeout-minutes` on all jobs. Implement concurrency controls to cancel redundant runs on the same branch. |

---

### P-E-001 — Elevation of Privilege | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Elevation of Privilege |
| **Surface** | CI/CD Pipeline |
| **Severity** | CRITICAL |
| **Affected Component** | GitHub Actions `GITHUB_TOKEN` |
| **Attack Scenario** | A compromised or misconfigured GitHub Actions workflow step gains access to `GITHUB_TOKEN` with write permissions, enabling push to protected branches or creation of releases without review. |
| **MITRE ATT&CK** | T1078.004 – Valid Accounts: Cloud Accounts |
| **Mitigation** | Set `permissions: read-all` at the workflow level; grant write scopes only to specific jobs that require it. Audit token scope quarterly. Use environment protection rules for release jobs. |

---

## Surface 2: Target Flask Application

### Summary

| Threat ID | Category | Severity | Affected Component |
|---|---|---|---|
| A-S-001 | Spoofing | HIGH | `app.py` – Authentication Endpoint |
| A-T-001 | Tampering | CRITICAL | `app.py` – `/query` Route (SQLi Sink) |
| A-T-002 | Tampering | CRITICAL | `app.py` – Deserialization Endpoint |
| A-R-001 | Repudiation | MEDIUM | `app.py` – Logging Configuration |
| A-I-001 | Information Disclosure | CRITICAL | `app.py` – Hardcoded Secrets |
| A-I-002 | Information Disclosure | HIGH | `app.py` – Flask Configuration (`debug=True`) |
| A-D-001 | Denial of Service | MEDIUM | `app.py` – All Endpoints (No Rate Limiting) |
| A-E-001 | Elevation of Privilege | CRITICAL | Dockerfile – Container Runtime Configuration |

---

### A-S-001 — Spoofing | HIGH

| Field | Detail |
|---|---|
| **Category** | Spoofing |
| **Surface** | Target Flask Application |
| **Severity** | HIGH |
| **Affected Component** | `app.py` – Authentication Endpoint |
| **OWASP Category** | A07:2021 – Identification and Authentication Failures |
| **Attack Scenario** | Attacker exploits the broken authentication endpoint to bypass session validation and impersonate an authenticated user by forging session tokens. |
| **MITRE ATT&CK** | T1078 – Valid Accounts |
| **Mitigation** | Replace custom auth with a hardened library (Flask-Login + bcrypt). Implement token expiry and rotation. Add multi-factor authentication hook. **Detected by:** Bandit (B105/B106), Semgrep auth rules. |

---

### A-T-001 — Tampering | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Tampering |
| **Surface** | Target Flask Application |
| **Severity** | CRITICAL |
| **Affected Component** | `app.py` – `/query` Route (SQLi Sink) |
| **OWASP Category** | A03:2021 – Injection |
| **Attack Scenario** | SQL injection in the query endpoint allows an attacker to modify database records, escalate privileges, or drop tables via unsanitized user input. |
| **MITRE ATT&CK** | T1190 – Exploit Public-Facing Application |
| **Mitigation** | Use parameterized queries (SQLAlchemy ORM). Apply input validation via Flask-WTF. Implement WAF rule at the reverse proxy layer. **Detected by:** Semgrep (`python.flask.security.injection.tainted-sql-string`), Bandit (B608), ZAP active scan. |

---

### A-T-002 — Tampering | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Tampering |
| **Surface** | Target Flask Application |
| **Severity** | CRITICAL |
| **Affected Component** | `app.py` – Deserialization Endpoint |
| **OWASP Category** | A08:2021 – Software and Data Integrity Failures |
| **Attack Scenario** | Insecure deserialization of untrusted pickle data allows an attacker to execute arbitrary Python code via a crafted serialized object submitted to the API. |
| **MITRE ATT&CK** | T1059.006 – Command and Scripting Interpreter: Python |
| **Mitigation** | Replace `pickle` with JSON or MessagePack for all deserialization. Implement strict type validation before deserialization. **Detected by:** Bandit (B301/B302), Semgrep deserialization rules, Wazuh rule 100003. |

---

### A-R-001 — Repudiation | MEDIUM

| Field | Detail |
|---|---|
| **Category** | Repudiation |
| **Surface** | Target Flask Application |
| **Severity** | MEDIUM |
| **Affected Component** | `app.py` – Logging Configuration |
| **Attack Scenario** | Application lacks structured request logging; attackers can perform actions (SQLi attempts, auth bypass) without any audit trail, preventing incident investigation. |
| **MITRE ATT&CK** | T1070 – Indicator Removal |
| **Mitigation** | Implement structured JSON logging (`python-json-logger`) for all request/response events. Forward to Wazuh for correlation. Include request ID, user ID, IP, and action in every log entry. |

---

### A-I-001 — Information Disclosure | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Surface** | Target Flask Application |
| **Severity** | CRITICAL |
| **Affected Component** | `app.py` – Hardcoded Secrets |
| **OWASP Category** | A02:2021 – Cryptographic Failures |
| **Attack Scenario** | Hardcoded AWS secret key and database password embedded in `app.py` source are exposed when the repository is public or the image is pushed to a container registry. |
| **MITRE ATT&CK** | T1552.001 – Unsecured Credentials: Credentials in Files |
| **Mitigation** | Move all secrets to environment variables injected at runtime via Docker Compose secrets or GitHub Actions encrypted secrets. **Detected by:** Trufflehog (git history scan), Semgrep secrets rules. |

---

### A-I-002 — Information Disclosure | HIGH

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Surface** | Target Flask Application |
| **Severity** | HIGH |
| **Affected Component** | `app.py` – Flask Configuration (`debug=True`) |
| **OWASP Category** | A05:2021 – Security Misconfiguration |
| **Attack Scenario** | Flask debug mode enabled in production (`debug=True`) exposes full stack traces, internal file paths, and the interactive Werkzeug debugger to any client on error. |
| **MITRE ATT&CK** | T1082 – System Information Discovery |
| **Mitigation** | Set `debug=False` in production; control via `FLASK_ENV` environment variable. **Detected by:** Semgrep and Bandit (`debug=True` flag); Trivy flags the base image misconfiguration. Enforce via policy gate threshold. |

---

### A-D-001 — Denial of Service | MEDIUM

| Field | Detail |
|---|---|
| **Category** | Denial of Service |
| **Surface** | Target Flask Application |
| **Severity** | MEDIUM |
| **Affected Component** | `app.py` – All Endpoints (No Rate Limiting) |
| **Attack Scenario** | Absence of rate limiting on authentication and API endpoints allows an attacker to perform credential stuffing or resource exhaustion via high-volume request flooding. |
| **MITRE ATT&CK** | T1499.002 – Service Exhaustion Flood |
| **Mitigation** | Integrate Flask-Limiter for per-endpoint rate limiting. Configure Wazuh rule 100002 to detect repeated 401 responses indicating brute force. Add circuit breaker at reverse proxy. |

---

### A-E-001 — Elevation of Privilege | CRITICAL

| Field | Detail |
|---|---|
| **Category** | Elevation of Privilege |
| **Surface** | Target Flask Application |
| **Severity** | CRITICAL |
| **Affected Component** | Dockerfile – Container Runtime Configuration |
| **OWASP Category** | A05:2021 – Security Misconfiguration |
| **Attack Scenario** | Container runs as root (`USER` instruction absent in Dockerfile). Combined with insecure deserialization (A-T-002), an RCE exploit escapes application context with host root privileges. |
| **MITRE ATT&CK** | T1611 – Escape to Host |
| **Mitigation** | Add `USER appuser` (non-root UID 1000) to Dockerfile. Set read-only filesystem where possible. **Detected by:** Trivy misconfiguration scan. Validate with `docker inspect` checking `User` field in container config. |

---

## Threat Coverage Summary

| Surface | STRIDE Categories Covered | Critical | High | Medium |
|---|---|---|---|---|
| CI/CD Pipeline Infrastructure | S, T, R, I, D, E | 2 (P-T-001, P-E-001) | 3 (P-S-001, P-T-002, P-I-002) | 3 (P-R-001, P-I-001, P-D-001) |
| Target Flask Application | S, T, R, I, D, E | 4 (A-T-001, A-T-002, A-I-001, A-E-001) | 2 (A-S-001, A-I-002) | 2 (A-R-001, A-D-001) |
| **TOTAL** | All 6 categories | **6** | **5** | **5** |
