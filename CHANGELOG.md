# Changelog

All notable changes to BreachPilot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Multi-target scanning support
- Real CVE database integration (NVD API)
- PDF report generation
- GUI dashboard (web-based)
- Plugin system for custom agents
- MITRE ATT&CK framework mapping
- Docker containerization
- Enhanced logging and audit trails

## [0.1.0] - 2024-09-04

### Added
- Initial release of BreachPilot
- CrewAI-based agent architecture with three core agents:
  - **ReconAgent**: Network reconnaissance using nmap
  - **PoCAgent**: CVE analysis with human approval
  - **ReportAgent**: Markdown report generation
- Human-in-the-Loop design for safety:
  - User approval required for CVE selection
  - No automatic exploitation
  - Clear consent prompts for all risky operations
- Command-line interface with Rich console output:
  - `--target` for specifying scan targets
  - `--output` for custom report filenames
  - `--verbose` for detailed logging
- Core scanning capabilities:
  - Nmap port scanning with service detection
  - CVE database lookup (embedded)
  - Service-to-vulnerability mapping
- Report generation:
  - Professional Markdown format
  - Executive summary and technical findings
  - Remediation recommendations
  - Methodology documentation
- Security features:
  - Input validation for target specification
  - Safe default scan parameters
  - Comprehensive logging and audit trails
- Documentation:
  - Installation and usage guides
  - Security considerations
  - Architecture overview
  - Contributing guidelines
- Testing framework:
  - Unit tests for core components
  - Integration tests for workflows
  - Security validation tests
  - CI/CD pipeline setup
- Development tools:
  - Installation scripts
  - Demo examples
  - Code quality tools (Black, Flake8, isort)
  - Test automation scripts

### Security
- Implemented input validation for all user inputs
- Added timeout protection for external tool execution
- Secure handling of API keys and sensitive data
- Safe-by-default configuration with user approval gates

### Dependencies
- CrewAI >= 0.28.0 for AI agent orchestration
- Anthropic >= 0.20.0 for Claude API integration
- Click >= 8.1.0 for CLI interface
- Rich >= 13.0.0 for enhanced console output
- python-nmap >= 0.7.1 for network scanning
- requests >= 2.31.0 for HTTP operations