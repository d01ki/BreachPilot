"""Tests for BreachPilot agents."""

import pytest
import json
from unittest.mock import patch, MagicMock

from breachpilot.core.agents import ReconAgent, PoCAgent, ReportAgent
from breachpilot.core.agents import nmap_scan, get_cve_info, generate_markdown_report


class TestReconAgent:
    """Test ReconAgent functionality."""
    
    def test_agent_creation(self):
        """Test ReconAgent creation."""
        agent = ReconAgent()
        assert agent.agent is not None
        assert agent.agent.role == "Reconnaissance Specialist"
    
    @patch('subprocess.run')
    def test_nmap_scan_success(self, mock_run):
        """Test successful nmap scan."""
        # Mock successful nmap execution
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Nmap scan results"
        
        result = nmap_scan("192.168.1.1")
        assert "Nmap scan results" in result
    
    @patch('subprocess.run')
    def test_nmap_scan_failure(self, mock_run):
        """Test failed nmap scan."""
        # Mock failed nmap execution
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Nmap error"
        
        result = nmap_scan("192.168.1.1")
        assert "Scan failed" in result


class TestPoCAgent:
    """Test PoCAgent functionality."""
    
    def test_agent_creation(self):
        """Test PoCAgent creation."""
        agent = PoCAgent()
        assert agent.agent is not None
        assert agent.agent.role == "Vulnerability Analyst"
    
    def test_get_cve_info(self):
        """Test CVE information retrieval."""
        result = get_cve_info("microsoft-ds", "Windows 7")
        data = json.loads(result)
        
        assert data["service"] == "microsoft-ds"
        assert data["version"] == "Windows 7"
        assert "CVE-2017-0144" in data["cves"]


class TestReportAgent:
    """Test ReportAgent functionality."""
    
    def test_agent_creation(self):
        """Test ReportAgent creation."""
        agent = ReportAgent()
        assert agent.agent is not None
        assert agent.agent.role == "Security Report Writer"
    
    @patch('builtins.open', create=True)
    def test_generate_markdown_report(self, mock_open):
        """Test markdown report generation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        test_data = json.dumps({
            "target": "192.168.1.1",
            "scan_summary": "Test scan",
            "vulnerability_summary": "Test vulnerabilities"
        })
        
        result = generate_markdown_report(test_data, "test_report.md")
        
        assert "successfully generated" in result
        mock_file.write.assert_called_once()


class TestTools:
    """Test individual tools."""
    
    def test_cve_database_coverage(self):
        """Test CVE database has expected services."""
        # Test known service
        result = get_cve_info("microsoft-ds", "Windows 7")
        data = json.loads(result)
        assert len(data["cves"]) > 0
        
        # Test unknown service falls back to default
        result = get_cve_info("unknown-service", "1.0")
        data = json.loads(result)
        assert data["cves"] == []