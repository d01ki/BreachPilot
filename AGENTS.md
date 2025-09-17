# BreachPilot AI Agents Documentation

## Overview

BreachPilot employs a multi-agent AI system powered by CrewAI to automate penetration testing workflows. This system combines specialized AI agents with Claude and OpenAI APIs to provide comprehensive security assessment capabilities.

## AI Agent Architecture

### Core Components

1. **AI Orchestrator** (`src/agents/ai_orchestrator.py`)
   - Central coordination system for all AI agents
   - Manages CrewAI workflow execution
   - Handles API client initialization (Claude & OpenAI)
   - Provides unified interface for agent interactions

2. **CrewAI Integration**
   - Multi-agent collaborative framework
   - Sequential and hierarchical agent workflows  
   - Tool-based agent capabilities
   - Automated task delegation and execution

3. **Claude AI Integration**
   - Primary AI model for report generation
   - Advanced reasoning for vulnerability analysis
   - Natural language processing for findings synthesis
   - Executive summary generation

4. **OpenAI Integration**
   - Supplementary analysis capabilities
   - Alternative reasoning for cross-validation
   - Enhanced natural language understanding

## Specialized AI Agents

### 1. Vulnerability Scan Analyst
- **Role**: Expert penetration tester specializing in network analysis
- **Goal**: Analyze network scan results to identify security vulnerabilities and attack vectors
- **Tools**: `ScanAnalysisTool`
- **Capabilities**:
  - Port service enumeration analysis
  - Vulnerability pattern recognition
  - Risk assessment and prioritization
  - Active Directory environment detection
  - CVE-2020-1472 (Zerologon) identification

### 2. Exploit Research Specialist  
- **Role**: Security researcher focused on exploit evaluation
- **Goal**: Research and evaluate Proof of Concept exploits for identified vulnerabilities
- **Tools**: `PoCSearchTool`
- **Capabilities**:
  - GitHub repository analysis and scoring
  - ExploitDB integration
  - Exploit quality assessment
  - Reliability and impact evaluation
  - Source code analysis and ranking

### 3. Exploit Execution Analyst
- **Role**: Penetration tester specializing in exploit analysis
- **Goal**: Analyze exploit execution results and provide actionable insights
- **Tools**: `ExploitAnalysisTool`
- **Capabilities**:
  - Exploit success/failure determination
  - Log analysis and interpretation
  - Impact assessment
  - Remediation recommendation generation
  - Timeline analysis of attack execution

### 4. Security Report Writer
- **Role**: Senior security consultant focused on documentation
- **Goal**: Generate comprehensive penetration testing reports
- **Tools**: Direct Claude API integration
- **Capabilities**:
  - Executive summary creation
  - Technical findings synthesis
  - Risk assessment documentation
  - Business impact analysis
  - Professional report formatting

## AI-Powered Tools

### ScanAnalysisTool
```python
class ScanAnalysisTool(BreachPilotTool):
    name: str = "scan_analysis"
    description: str = "Analyze network scan results and identify potential vulnerabilities"
```
- Processes Nmap scan outputs
- Identifies open ports and services
- Detects Domain Controller characteristics
- Flags Kerberos services (Zerologon risk)
- Generates structured vulnerability assessments

### PoCSearchTool
```python
class PoCSearchTool(BreachPilotTool):
    name: str = "poc_search" 
    description: str = "Search and rank Proof of Concept exploits from various sources"
```
- GitHub API integration for repository search
- ExploitDB metadata retrieval
- Multi-factor scoring algorithm:
  - Star count and popularity
  - Recent activity and maintenance
  - Programming language preference
  - Keyword relevance matching
- Quality and reliability assessment

### ExploitAnalysisTool
```python
class ExploitAnalysisTool(BreachPilotTool):
    name: str = "exploit_analysis"
    description: str = "Analyze exploit execution results and determine success/failure"
```
- Log parsing and analysis
- Success indicator detection
- Failure pattern recognition
- Timeline reconstruction
- Remediation guidance generation

## Workflow Pipeline

### Phase 1: Network Reconnaissance
1. **Traditional Scanning**: Nmap + NSE scripts
2. **AI Analysis**: Scan Analyst processes results
3. **Vulnerability Identification**: AI flags potential issues
4. **Risk Prioritization**: Automated threat ranking

### Phase 2: Exploit Research
1. **PoC Discovery**: Multi-source exploit search
2. **AI Evaluation**: Research Specialist scores options
3. **Quality Assessment**: Reliability and impact analysis
4. **Selection Logic**: Best candidate identification

### Phase 3: Controlled Exploitation
1. **PoC Execution**: Controlled testing environment
2. **Result Capture**: Comprehensive logging
3. **AI Analysis**: Execution Analyst processes outcomes
4. **Impact Assessment**: Success/failure determination

### Phase 4: Report Generation
1. **Data Synthesis**: All findings aggregation
2. **Claude Processing**: Comprehensive analysis
3. **Report Creation**: Professional documentation
4. **Multi-format Output**: Markdown and PDF generation

## Configuration Requirements

### Required API Keys
- **Anthropic Claude**: Essential for report generation
- **OpenAI**: Optional for supplementary analysis
- **GitHub Token**: Optional for enhanced PoC search

### Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GITHUB_TOKEN="ghp_..."
```

### Agent Configuration
```python
# AI Orchestrator initialization
orchestrator = AIAgentOrchestrator()

# Agent creation with tools
scan_agent = orchestrator.create_scan_agent()
poc_agent = orchestrator.create_poc_agent()
exploit_agent = orchestrator.create_exploit_agent()
report_agent = orchestrator.create_report_agent()
```

## Advanced Features

### Multi-Agent Collaboration
- **Sequential Processing**: Agents work in defined order
- **Data Sharing**: Results passed between agents
- **Cross-Validation**: Multiple AI perspectives
- **Quality Assurance**: Automated consistency checks

### Intelligent Scoring Algorithms
- **PoC Quality Metrics**: Multi-factor evaluation
- **Risk Assessment**: Automated CVSS integration
- **Priority Ranking**: Business impact consideration
- **Confidence Scoring**: Reliability indicators

### Professional Report Generation
- **Executive Summaries**: Business-focused insights
- **Technical Details**: Comprehensive findings
- **Remediation Guidance**: Actionable recommendations
- **Visual Formatting**: Professional presentation

## CVE-2020-1472 (Zerologon) Specialization

### Detection Capabilities
- **Port Analysis**: Kerberos service identification (88/tcp)
- **Service Enumeration**: Netlogon RPC detection
- **Domain Controller Recognition**: AD environment analysis
- **Vulnerability Confirmation**: Automated testing

### Exploit Integration
- **GitHub Sources**: Curated PoC repositories
- **Quality Assessment**: Code analysis and scoring
- **Controlled Execution**: Safe testing environment
- **Impact Analysis**: Domain compromise assessment

### Reporting Features
- **CVSS 10.0 Highlighting**: Critical severity emphasis
- **Business Impact**: Domain compromise implications
- **Remediation Steps**: Microsoft patch guidance
- **Timeline Analysis**: Attack progression documentation

## Security Considerations

### Ethical Usage
- **Authorization Required**: Controlled environment testing
- **Lab Environment Only**: No production system testing
- **Responsible Disclosure**: Vulnerability reporting guidelines
- **Legal Compliance**: Penetration testing authorization

### Data Protection
- **API Key Security**: Local storage only
- **Result Isolation**: Job-specific directories
- **Log Management**: Secure result handling
- **Privacy Protection**: No data transmission

## Performance Optimization

### Agent Efficiency
- **Parallel Processing**: Where applicable
- **Caching Mechanisms**: API result storage
- **Rate Limiting**: Respectful API usage
- **Resource Management**: Memory and CPU optimization

### Scalability Features
- **Background Processing**: Threading implementation
- **Progress Tracking**: Real-time status updates
- **Error Handling**: Graceful failure recovery
- **Resource Cleanup**: Automatic job management

## Future Enhancements

### Planned Features
- **Additional CVEs**: Expanded vulnerability coverage
- **More AI Models**: Integration diversity
- **Advanced Analytics**: Machine learning insights
- **Cloud Integration**: Distributed processing

### Research Areas
- **Adaptive Learning**: AI model improvement
- **Automated Patching**: Remediation automation  
- **Threat Intelligence**: External feed integration
- **Behavioral Analysis**: Advanced attack detection

## Usage Examples

### Basic Scan Analysis
```python
orchestrator = get_orchestrator()
result = orchestrator.analyze_scan_results(scan_data, work_dir)
```

### PoC Research
```python
poc_result = orchestrator.research_poc(vulnerability_info, work_dir)
```

### Comprehensive Report
```python
report = orchestrator.generate_comprehensive_report(all_data, work_dir)
```

## Troubleshooting

### Common Issues
1. **API Key Configuration**: Verify correct format and permissions
2. **Network Connectivity**: Ensure API endpoint access
3. **Resource Limits**: Monitor memory and CPU usage
4. **Rate Limiting**: Implement appropriate delays

### Debug Information
- **Verbose Logging**: Enable detailed output
- **Error Tracking**: Comprehensive exception handling
- **Performance Metrics**: Timing and resource monitoring
- **Agent Communication**: Inter-agent data flow validation

## Support and Documentation

### Additional Resources
- **CrewAI Documentation**: Official framework guide
- **Claude API Reference**: Anthropic integration details
- **OpenAI API Guide**: GPT integration documentation
- **GitHub API Docs**: Repository search capabilities

For technical support and feature requests, please refer to the project repository or contact the development team.
