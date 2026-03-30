# Security Requirements

## Derivation Methodology

Security requirements are derived directly from STRIDE findings documented in `stride-threat-model.md`. Each requirement is written as a SHALL/MUST statement conforming to RFC 2119 language to ensure testability and auditability.

Requirements are prioritized as:

- **P1** – Pipeline-blocking: violation causes `evaluate.py` to exit with code `1`, halting deployment
- **P2** – Monitoring/operational: violation triggers alerting or audit action but does not block deployment

Each requirement maps to:
- A **CIS Control v8** identifier
- A **NIST SP 800-218 (SSDF)** practice identifier
- The **implementing tool or pipeline component**
- The **STRIDE threat ID(s)** it mitigates

---

## Security Requirements Matrix

### SRQ-001 — Pipeline Workflow Integrity

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Pipeline Workflow Integrity |
| **Requirement** | The CI/CD pipeline MUST enforce code review approval from designated CODEOWNERS before any workflow modification is merged into the `main` branch. All third-party GitHub Actions MUST be pinned to full commit SHAs. Workflow-level permissions MUST default to `contents: read`. |
| **CIS Control v8** | CIS Control 6.7 – Centralize Access Control |
| **NIST SP 800-218** | PW.4.1 – Protect code from unauthorized access and tampering |
| **Implementing Control** | GitHub branch protection rules; CODEOWNERS file; SHA-pinned Actions |
| **STRIDE Ref** | P-S-001, P-T-001 |

---

### SRQ-002 — Policy-as-Code Tamper Detection

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Policy-as-Code Tamper Detection |
| **Requirement** | Pipeline policy configuration files (`pipeline/policy/policy.yml`) MUST have their cryptographic hash verified at pipeline runtime. Any deviation from the expected hash MUST cause an immediate pipeline failure and alert. All policy changes MUST require GPG commit signing. |
| **CIS Control v8** | CIS Control 10.5 – Enable Anti-Exploitation Features |
| **NIST SP 800-218** | PW.4.4 – Verify the integrity of software before installation |
| **Implementing Control** | SHA-256 hash verification step in `evaluate.py`; GPG signing enforced via branch protection |
| **STRIDE Ref** | P-T-001 |

---

### SRQ-003 — Supply Chain Dependency Verification

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Supply Chain Dependency Verification |
| **Requirement** | All pipeline tool dependencies and third-party GitHub Actions MUST be pinned to exact versions or full commit SHAs. Automated SCA MUST run against the pipeline's own `requirements.txt` on every pipeline execution. |
| **CIS Control v8** | CIS Control 16.3 – Perform Application Penetration Testing |
| **NIST SP 800-218** | PO.1.3 – Identify and manage supply chain security requirements |
| **Implementing Control** | OWASP Dependency-Check run against `pipeline/` dependencies; SHA-pinned Actions in workflow YAML |
| **STRIDE Ref** | P-T-002 |

---

### SRQ-004 — Git History Secret Detection

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Git History Secret Detection |
| **Requirement** | The pipeline MUST scan the full git commit history on every run using Trufflehog. Any detected credential — live or historical — MUST be treated as a P1 finding and cause pipeline failure via `fail_on_new_secrets: true` in `policy.yml`. |
| **CIS Control v8** | CIS Control 3.11 – Encrypt Sensitive Data at Rest |
| **NIST SP 800-218** | PW.1.2 – Store and transmit credentials securely |
| **Implementing Control** | Trufflehog (`--since-commit` full history mode); policy gate `fail_on_new_secrets` flag |
| **STRIDE Ref** | P-R-001, A-I-001 |

---

### SRQ-005 — Least-Privilege GITHUB_TOKEN Scope

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Least-Privilege GITHUB_TOKEN Scope |
| **Requirement** | All GitHub Actions workflows MUST declare `permissions: read-all` at the workflow level. Write permissions MUST be scoped only to specific jobs that explicitly require them (e.g., release creation). Token scope MUST be audited on a quarterly basis. |
| **CIS Control v8** | CIS Control 5.4 – Restrict Administrator Privileges to Dedicated Admin Accounts |
| **NIST SP 800-218** | PO.2.2 – Implement the principle of least privilege |
| **Implementing Control** | Workflow-level `permissions:` block in `.github/workflows/devsecops-pipeline.yml` |
| **STRIDE Ref** | P-E-001 |

---

### SRQ-006 — Static Analysis: Injection Vulnerability Detection

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Static Analysis – Injection Vulnerability Detection |
| **Requirement** | Every code commit MUST be scanned by Semgrep (OWASP ruleset + custom rules) and Bandit. Any CRITICAL or HIGH severity injection finding (SQL injection, command injection) MUST cause pipeline failure. |
| **CIS Control v8** | CIS Control 16.12 – Implement Code-Level Security Checks |
| **NIST SP 800-218** | PW.7.2 – Test executable code to identify vulnerabilities |
| **Implementing Control** | Semgrep (`python.flask.security.injection.tainted-sql-string`), Bandit (B608); policy gate zero-tolerance for CRITICAL |
| **STRIDE Ref** | A-T-001 |

---

### SRQ-007 — Deserialization Safety

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Deserialization Safety |
| **Requirement** | The pipeline MUST detect and fail on use of Python `pickle` or `marshal` deserialization with untrusted data. Findings categorized as CRITICAL by Bandit (B301/B302) MUST block deployment via the policy gate. |
| **CIS Control v8** | CIS Control 16.12 – Implement Code-Level Security Checks |
| **NIST SP 800-218** | PW.7.2 – Test executable code to identify vulnerabilities |
| **Implementing Control** | Bandit (B301/B302); Semgrep deserialization rules; Wazuh rule 100003 (runtime detection) |
| **STRIDE Ref** | A-T-002 |

---

### SRQ-008 — Runtime Secret Elimination

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Runtime Secret Elimination |
| **Requirement** | No credentials, API keys, or passwords MAY be present in application source code, Dockerfiles, or configuration files committed to the repository. All secrets MUST be injected at runtime via environment variables or GitHub Actions encrypted secrets. |
| **CIS Control v8** | CIS Control 3.11 – Encrypt Sensitive Data at Rest |
| **NIST SP 800-218** | PW.1.2 – Store and transmit credentials securely |
| **Implementing Control** | Trufflehog (git history scan); Semgrep secrets rules; Docker Compose secrets injection |
| **STRIDE Ref** | A-I-001 |

---

### SRQ-009 — Container Non-Root Execution

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Container Non-Root Execution |
| **Requirement** | All container images MUST be built with a non-root `USER` instruction (UID ≥ 1000). Trivy misconfiguration scan MUST flag any image built without a non-root user as a CRITICAL finding. |
| **CIS Control v8** | CIS Control 4.1 – Establish and Maintain a Secure Configuration Process |
| **NIST SP 800-218** | PO.4.1 – Define and manage security requirements for the software |
| **Implementing Control** | Trivy misconfiguration scan; Dockerfile `USER appuser` (UID 1000) instruction |
| **STRIDE Ref** | A-E-001 |

---

### SRQ-010 — Known Vulnerability Threshold Enforcement

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Known Vulnerability Threshold Enforcement |
| **Requirement** | The policy gate MUST enforce zero tolerance for CRITICAL CVEs across SAST, SCA, and container scan outputs. HIGH findings MUST not exceed 3. Any threshold violation MUST cause `evaluate.py` to exit with code `1`. |
| **CIS Control v8** | CIS Control 7.4 – Manage Default Accounts on Enterprise Assets |
| **NIST SP 800-218** | RV.1.3 – Analyze discovered vulnerabilities to determine their potential impact |
| **Implementing Control** | `pipeline/policy/evaluate.py`; `pipeline/policy/policy.yml` thresholds (`critical: 0`, `high: 3`, `medium: 10`) |
| **STRIDE Ref** | A-T-001, A-T-002, A-I-002 |

---

### SRQ-011 — DAST Active Scan Coverage

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | DAST Active Scan Coverage |
| **Requirement** | OWASP ZAP MUST perform a spider + active scan against every deployed build. Findings MUST be mapped to OWASP Top 10 categories and normalized into the standard JSON schema before policy gate evaluation. |
| **CIS Control v8** | CIS Control 16.13 – Conduct Application Penetration Testing |
| **NIST SP 800-218** | PW.8.2 – Conduct penetration testing |
| **Implementing Control** | `pipeline/dast/zap-scan.py`; `pipeline/dast/attack-mapping.json`; ZAP daemon mode |
| **STRIDE Ref** | A-T-001, A-S-001, A-D-001 |

---

### SRQ-012 — Runtime Anomaly Detection

| Field | Detail |
|---|---|
| **Priority** | P2 |
| **Title** | Runtime Anomaly Detection |
| **Requirement** | Wazuh MUST monitor all target application container logs in real time. Custom detection rules MUST fire within 60 seconds of a matching event. Rules MUST cover at minimum: SQLi attempts (rule 100001), brute force authentication (rule 100002), and pickle deserialization events (rule 100003). |
| **CIS Control v8** | CIS Control 8.11 – Conduct Audit Log Reviews |
| **NIST SP 800-218** | RV.2.2 – Assess, prioritize, and remediate vulnerabilities |
| **Implementing Control** | Wazuh manager + agent (Docker Compose); `wazuh/rules/custom-rules.xml` |
| **STRIDE Ref** | A-R-001, A-T-001, A-T-002 |

---

### SRQ-013 — Structured Audit Logging

| Field | Detail |
|---|---|
| **Priority** | P2 |
| **Title** | Structured Audit Logging |
| **Requirement** | The target application MUST emit structured JSON logs for every request, including: request ID, user ID, source IP, endpoint, HTTP method, response code, and timestamp. Logs MUST be forwarded to Wazuh for correlation. |
| **CIS Control v8** | CIS Control 8.2 – Collect Audit Logs |
| **NIST SP 800-218** | PO.3.2 – Implement supporting toolchains |
| **Implementing Control** | `python-json-logger` in `app/app.py`; Wazuh log forwarding agent configuration |
| **STRIDE Ref** | A-R-001 |

---

### SRQ-014 — Debug Mode Prohibition in Production

| Field | Detail |
|---|---|
| **Priority** | P1 |
| **Title** | Debug Mode Prohibition in Production |
| **Requirement** | Flask applications MUST NOT be deployed with `debug=True`. `FLASK_ENV` MUST be set via environment variable injection, not hardcoded. Semgrep and Bandit MUST flag `debug=True` as a HIGH finding. |
| **CIS Control v8** | CIS Control 4.1 – Establish and Maintain a Secure Configuration Process |
| **NIST SP 800-218** | PW.4.1 – Protect code from unauthorized access and tampering |
| **Implementing Control** | Semgrep (`flask.debug.true` rule); Bandit; Docker Compose `FLASK_ENV=production` environment variable |
| **STRIDE Ref** | A-I-002 |

---

## Requirements Summary

| ID | Title | Priority | STRIDE Ref | CIS Control | NIST SSDF |
|---|---|---|---|---|---|
| SRQ-001 | Pipeline Workflow Integrity | P1 | P-S-001, P-T-001 | 6.7 | PW.4.1 |
| SRQ-002 | Policy-as-Code Tamper Detection | P1 | P-T-001 | 10.5 | PW.4.4 |
| SRQ-003 | Supply Chain Dependency Verification | P1 | P-T-002 | 16.3 | PO.1.3 |
| SRQ-004 | Git History Secret Detection | P1 | P-R-001, A-I-001 | 3.11 | PW.1.2 |
| SRQ-005 | Least-Privilege GITHUB_TOKEN Scope | P1 | P-E-001 | 5.4 | PO.2.2 |
| SRQ-006 | Static Analysis: Injection Detection | P1 | A-T-001 | 16.12 | PW.7.2 |
| SRQ-007 | Deserialization Safety | P1 | A-T-002 | 16.12 | PW.7.2 |
| SRQ-008 | Runtime Secret Elimination | P1 | A-I-001 | 3.11 | PW.1.2 |
| SRQ-009 | Container Non-Root Execution | P1 | A-E-001 | 4.1 | PO.4.1 |
| SRQ-010 | Known Vulnerability Threshold Enforcement | P1 | A-T-001, A-T-002, A-I-002 | 7.4 | RV.1.3 |
| SRQ-011 | DAST Active Scan Coverage | P1 | A-T-001, A-S-001, A-D-001 | 16.13 | PW.8.2 |
| SRQ-012 | Runtime Anomaly Detection | P2 | A-R-001, A-T-001, A-T-002 | 8.11 | RV.2.2 |
| SRQ-013 | Structured Audit Logging | P2 | A-R-001 | 8.2 | PO.3.2 |
| SRQ-014 | Debug Mode Prohibition in Production | P1 | A-I-002 | 4.1 | PW.4.1 |

**P1 count:** 12 (pipeline-blocking)
**P2 count:** 2 (monitoring/operational)
**Total:** 14 requirements (SRQ-001 – SRQ-014)
