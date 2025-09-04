"""Tests for BreachPilot crew functionality."""

import pytest
from unittest.mock import patch, MagicMock

from breachpilot.core.crew import BreachPilotCrew


class TestBreachPilotCrew:
    """Test BreachPilotCrew functionality."""
    
    def test_crew_initialization(self):
        """Test crew initialization."""
        crew = BreachPilotCrew(target="192.168.1.1")
        
        assert crew.target == "192.168.1.1"
        assert crew.output_file == "report.md"
        assert crew.verbose == False
        assert crew.recon_agent is not None
        assert crew.poc_agent is not None
        assert crew.report_agent is not None
        assert crew.crew is not None
    
    def test_crew_with_custom_params(self):
        """Test crew with custom parameters."""
        crew = BreachPilotCrew(
            target="10.0.0.1",
            output_file="custom_report.md",
            verbose=True
        )
        
        assert crew.target == "10.0.0.1"
        assert crew.output_file == "custom_report.md"
        assert crew.verbose == True
    
    @patch('breachpilot.core.crew.Crew.kickoff')
    def test_crew_run_success(self, mock_kickoff):
        """Test successful crew execution."""
        mock_kickoff.return_value = "Test result"
        
        crew = BreachPilotCrew(target="192.168.1.1")
        result = crew.run()
        
        assert result['success'] == True
        assert result['target'] == "192.168.1.1"
        assert result['output_file'] == "report.md"
        assert 'summary' in result
    
    @patch('breachpilot.core.crew.Crew.kickoff')
    def test_crew_run_failure(self, mock_kickoff):
        """Test crew execution failure."""
        mock_kickoff.side_effect = Exception("Test error")
        
        crew = BreachPilotCrew(target="192.168.1.1")
        
        with pytest.raises(Exception) as exc_info:
            crew.run()
        
        assert "Test error" in str(exc_info.value)