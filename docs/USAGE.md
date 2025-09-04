# Usage Guide

## Basic Usage

### Quick Start
```bash
# Basic scan
breachpilot --target 192.168.1.10

# Custom output file
breachpilot --target 192.168.1.10 --output my_report.md

# Verbose output
breachpilot --target 192.168.1.10 --verbose
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|----------|
| `--target` | `-t` | Target IP address or hostname | Required |
| `--output` | `-o` | Output report filename | `report.md` |
| `--verbose` | `-v` | Enable detailed logging | `False` |

## Workflow Overview

BreachPilot follows a structured workflow with human-in-the-loop validation:

### 1. Reconnaissance Phase (Automated)
- **ReconAgent** performs nmap scan
- Discovers open ports and services
- Identifies service versions
- Results stored in JSON format

### 2. Vulnerability Analysis Phase (Human Approval Required)
- **PoCAgent** analyzes scan results
- Suggests potential CVEs based on services/versions
- **User approval required** for each CVE
- Only approved CVEs proceed to next phase

### 3. Report Generation Phase (Automated)
- **ReportAgent** compiles findings
- Generates comprehensive Markdown report
- Includes methodology and recommendations

## Interactive Prompts

### CVE Approval
During vulnerability analysis, you'll see prompts like:

```
🔍 CVE Candidates Found
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ CVE             ┃ Service   ┃ Severity  ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━┩
│ CVE-2017-0144   │ SMB       │ Critical  │
└─────────────────┴───────────┴───────────┘

Approve CVE-2017-0144 for further analysis? [y/N]:
```

**Response Options:**
- `y` or `yes`: Approve CVE for inclusion in report
- `n` or `no` (default): Skip this CVE
- `Ctrl+C`: Cancel entire scan