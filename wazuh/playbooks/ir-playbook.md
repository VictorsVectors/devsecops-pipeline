# Incident Response Playbook
## DevSecOps Pipeline — Automated SDLC Security Scanner

**Version:** 1.0
**Applies to:** Target Flask application monitored via Wazuh 4.7.3
**Detection source:** Custom Wazuh rules 100001, 100003, 100004

---

## Scenario 1: SQL Injection Attempt

**Maps to:** STRIDE threat A-T-001 | MITRE ATT&CK T1190 | SRQ-012

### Detection Criteria

Wazuh rule 100001 fires when the Flask application log contains SQL error strings including `OperationalError`, `ProgrammingError`, `UNION SELECT`, `syntax error`, `unrecognized token`, `no such column`, or `no such table`. These strings appear in application logs when unsanitized user input reaches a database query. The alert fires at severity level 10.

The alert will appear in the Wazuh dashboard under Security Events with the description: `Possible SQL injection attempt detected in Flask application logs`.

### Investigation Steps

1. Open the Wazuh dashboard and navigate to Security Events. Filter by rule ID 100001.
2. Identify the source IP and timestamp of the triggering log entry.
3. Pull the Flask application logs for the 10 minutes surrounding the alert:
docker logs flask-app --since 10m
4. Examine the request that produced the SQL error. Identify the endpoint, HTTP method, and parameter that contained the payload.
5. Check whether the injection succeeded by looking for unexpected data in subsequent responses or database state changes.
6. Search for prior requests from the same source IP to determine whether this is a targeted attack or automated scanner:
docker logs flask-app | grep <source-ip>

### Containment Actions

1. If the attack is active, block the source IP at the network level or via a reverse proxy rule.
2. If data exfiltration is confirmed, take the Flask container offline immediately:
docker compose -f wazuh-single-node.yml stop
docker stop flask-app
3. Preserve container logs before any restart:
docker logs flask-app > /tmp/incident-sqli-$(date +%Y%m%d%H%M%S).log
4. Notify the application owner and security team.

### Recovery Procedures

1. Replace the vulnerable string-formatted query with a parameterized query using SQLAlchemy named parameter syntax.
2. Run the SAST pipeline to confirm the fix is detected as remediated (Semgrep rule `flask-sqli-string-format` and Bandit B608 should no longer fire).
3. Redeploy the patched container image.
4. Update the policy gate HIGH threshold if the finding count has changed.
5. Document the incident and resolution in the pipeline run notes.

---

## Scenario 2: Brute Force Authentication Attack

**Maps to:** STRIDE threat A-S-001 | MITRE ATT&CK T1110 | SRQ-012

### Detection Criteria

Wazuh rule 100002 fires on any single 401 Unauthorized response at severity level 3. Wazuh rule 100003 fires when 5 or more 401 responses occur within 60 seconds from the same source, escalating to severity level 10. The alert description reads: `Possible brute force attack - 5 or more 401 responses in 60 seconds`.

### Investigation Steps

1. Open the Wazuh dashboard and navigate to Security Events. Filter by rule ID 100003.
2. Identify the source IP, the targeted endpoint, and the time window of the attack.
3. Pull authentication logs to determine the volume and pattern of attempts:
docker logs flask-app | grep "401"
4. Determine whether any attempts succeeded by looking for 200 responses from the same IP following a series of 401s.
5. Check whether the targeted username exists in the database — a successful compromise would show a session being established after repeated failures.
6. Review the request user-agent and payload pattern to distinguish automated tools from manual attempts.

### Containment Actions

1. Block the attacking IP at the network or reverse proxy layer.
2. If a successful login from the attacking IP is confirmed, immediately invalidate all active sessions:
docker exec flask-app python -c "from app import db; db.session.remove()"
3. Temporarily disable the authentication endpoint if the attack is ongoing:
docker exec flask-app touch /tmp/maintenance
4. Rotate any compromised credentials immediately.

### Recovery Procedures

1. Implement rate limiting on the authentication endpoint using Flask-Limiter.
2. Add account lockout after a configurable number of failed attempts.
3. Consider adding CAPTCHA or multi-factor authentication to the login flow.
4. Re-run the full pipeline to confirm no new vulnerabilities were introduced during remediation.
5. Update Wazuh rule 100003 timeframe or frequency thresholds based on observed attack patterns.

---

## Scenario 3: Pickle Deserialization RCE Attempt

**Maps to:** STRIDE threat A-T-002 | MITRE ATT&CK T1059.006 | SRQ-012

### Detection Criteria

Wazuh rule 100004 fires when the Flask application log contains strings matching `pickle.loads`, `deserializ`, or `Unpickling`. This fires at severity level 12 — the highest severity in this ruleset — because successful exploitation results in arbitrary Python code execution on the container. The alert description reads: `Pickle deserialization invoked at runtime - possible RCE attempt`.

### Investigation Steps

1. Open the Wazuh dashboard and navigate to Security Events. Filter by rule ID 100004.
2. Treat this alert as a confirmed critical incident until proven otherwise. Severity 12 warrants immediate response.
3. Identify the endpoint that received the pickle payload and the source IP:
docker logs flask-app | grep -i "pickle|deserializ"
4. Determine whether code execution occurred by checking for unexpected processes, file system changes, or outbound network connections from the container:
docker exec flask-app ps aux
docker exec flask-app find /tmp -newer /tmp -type f 2>/dev/null
5. Check container network activity for outbound connections that may indicate a reverse shell:
docker exec flask-app cat /proc/net/tcp
6. Preserve a forensic snapshot of the container before any action:
docker commit flask-app flask-app-forensic-$(date +%Y%m%d%H%M%S)
docker logs flask-app > /tmp/incident-rce-$(date +%Y%m%d%H%M%S).log

### Containment Actions

1. Immediately isolate the container by disconnecting it from the network:
docker network disconnect devsecops-pipeline_scan-net flask-app
2. Stop the container to terminate any active shell sessions:
docker stop flask-app
3. Do not restart the compromised container. Treat it as evidence.
4. Revoke any credentials or secrets that may have been exposed in the container environment.
5. Notify the security team and escalate to a full incident response process.

### Recovery Procedures

1. Replace `pickle.loads()` with JSON deserialization (`json.loads()`) for all untrusted input in the Flask application.
2. Add strict type validation before any deserialization operation.
3. Rebuild the container image from scratch using a clean base. Do not reuse the compromised image.
4. Run the full pipeline against the patched code. Confirm that Bandit B301/B302 and Semgrep `flask-pickle-loads-request-data` no longer fire.
5. Rotate all secrets that were present in the container environment at the time of the incident.
6. Update the Wazuh rule 100004 regex if new deserialization patterns are identified during the investigation.
7. Conduct a post-incident review and document findings in the methodology report.

---

## References

- STRIDE threat model: `Docs/Threat-Model/stride-threat-model.md`
- Security requirements: `Docs/Threat-Model/security-requirements.md`
- Custom detection rules: `wazuh/rules/custom-rules.xml`
- MITRE ATT&CK Enterprise Matrix v16.1: https://attack.mitre.org/
