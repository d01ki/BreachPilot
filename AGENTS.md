# BreachPilot Agents (PoC)

This document tracks the current scope and progress for each agent per the specification.

## 1) Scan Agent
- Purpose: Run Nmap against target (AD-focused) and save structured JSON.
- Status: Implemented
  - python-nmap preferred; subprocess fallback
  - Ports: 88, 135, 389, 445
  - Service/version detection, basic inferences (Kerberos, possible DC)
  - Output: `reports/scan.json` and in-memory status with phase tracking
- Next:
  - Add NSE scripts coverage report and parsing
  - Configurable ports and timeouts via settings

## 2) PoC Retrieval Agent
- Purpose: Given vulnerability (CVE-2020-1472), fetch PoC sources (GitHub/ExploitDB)
- Status: Implemented (metadata)
  - GitHub Search API with optional token
  - Collects top candidates and ExploitDB search link
  - Output: `reports/poc.json`
- Next:
  - Ranking/scoring, MCP integration, richer metadata

## 3) Exploit Agent
- Purpose: Execute PoC in a lab environment and capture logs
- Status: Implemented (placeholder PoC)
  - Generates a minimal Zerologon tester (445 reachability)
  - Executes only when authorized (LAB)
  - Output: `reports/exploit.log`, tail shown in UI
- Next:
  - Integrate real PoC (LAB-only), safety guards, detailed telemetry

## 4) Report Generator Agent
- Purpose: Combine scan/PoC/exploit into a report (Markdown/PDF)
- Status: Implemented (PoC)
  - Markdown with artifacts summary
  - Minimal PDF placeholder
- Next:
  - Claude/CrewAI narrative, HTML->PDF pipeline, templates

## Web UI
- Theme: Tailwind dark gradient with glass cards
- Pages:
  - Home: Start assessment
  - Status: Phase + scan summary + exploit log tail + download
  - Settings: Provider tokens (OpenAI/Anthropic/GitHub)
- Next:
  - Step progress indicator, live updates, masking secrets
