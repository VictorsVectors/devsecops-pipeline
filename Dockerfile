# VULN: Misconfig - A05:2021 - Security Misconfiguration
# Base image uses Python 2.7.14 on Debian Jessie, both EOL since 2020.
# Contains hundreds of unpatched CVEs. Detected by: Trivy image scan.
# In production, use python:3.12-slim-bookworm or distroless.
FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

# VULN: Misconfig - Supply chain risk: pip install without hash verification
# Allows dependency substitution attacks. No version pinning on pip/setuptools.
RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# VULN: Misconfig - A05:2021 - Container runs as root (no USER instruction)
# No USER instruction means the process runs as UID 0 (root).
# Combined with the pickle deserialization RCE (A-T-002), an attacker
# achieves host root access. Detected by: Trivy misconfiguration scan.
# Mitigation: Add 'RUN useradd -u 1000 appuser && USER appuser' before ENTRYPOINT.
ENTRYPOINT ["python"]

CMD ["app.py"]
