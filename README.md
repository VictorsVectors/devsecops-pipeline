# DevSecOps-Pipeline
# devsecops-pipeline

**Automated SDLC Security Scanner — DevSecOps Capstone**


## Overview

A fully automated DevSecOps pipeline that enforces security at every stage of the SDLC. Built around a deliberately vulnerable Flask application, this pipeline integrates SAST, SCA, secrets detection, container scanning, DAST, policy-as-code enforcement, and SIEM runtime monitoring.

## Pipeline Architecture

```

Code Commit → SAST/Secrets → SCA → Container Build → Container Scan → DAST → Policy Gate → Deploy → Wazuh Runtime Monitoring

```

## Deliverables

| Deliverable | Description | Tag |

|-------------|-------------|-----|

| D1 | Threat Model + Security Requirements

| D2 | CI/CD Pipeline + Design Report 

| D3 | Automated Report Generator + Methodology Report 

| D4 | Wazuh SIEM Integration + IR Playbook

| D5 | Final Technical Report + Portfolio Repo

## Repository Structure

| Directory | Purpose |

|-----------|---------|

| `.github/workflows/` | GitHub Actions pipeline definitions |

| `app/` | Intentionally vulnerable Flask target application |

| `pipeline/` | Security tool configurations and normalization scripts |

| `reporting/` | Automated report generator |

| `wazuh/` | Detection rules and IR playbooks |

| `docs/` | All formal deliverable documents |

| `outputs/` | Sample pipeline run artifacts |

> **Status:** 🚧 In progress — Week 1
