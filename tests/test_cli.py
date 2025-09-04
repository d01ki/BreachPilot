"""Tests for BreachPilot CLI."""

import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from breachpilot.cli import main


class TestCLI:
    """Test CLI functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        self.runner = CliRunner()
    
    def test_cli_help(self):
        """Test CLI help display."""
        result = self.runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert "BreachPilot" in result.output
        assert "--target" in result.output
        assert "--output" in result.output
        assert "--verbose" in result.output
    
    def test_cli_missing_target(self):
        """Test CLI with missing required target."""
        result = self.runner.invoke(main, [])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "Error" in result.output
    
    @patch('breachpilot.cli.BreachPilotCrew')
    def test_cli_basic_execution(self, mock_crew_class):
        """Test basic CLI execution."""
        # Mock the crew
        mock_crew = MagicMock()
        mock_crew.run.return_value = {
            'success': True,
            'summary': 'Test completed'
        }
        mock_crew_class.return_value = mock_crew
        
        result = self.runner.invoke(main, ['--target', '192.168.1.1'])
        
        # Should not exit with error
        assert result.exit_code == 0
        assert "BreachPilot" in result.output
    
    @patch('breachpilot.cli.BreachPilotCrew')
    def test_cli_with_options(self, mock_crew_class):
        """Test CLI with all options."""
        # Mock the crew
        mock_crew = MagicMock()
        mock_crew.run.return_value = {
            'success': True,
            'summary': 'Test completed'
        }
        mock_crew_class.return_value = mock_crew
        
        result = self.runner.invoke(main, [
            '--target', '192.168.1.1',
            '--output', 'custom_report.md',
            '--verbose'
        ])
        
        assert result.exit_code == 0
        # Verify crew was initialized with correct parameters
        mock_crew_class.assert_called_once_with(
            target='192.168.1.1',
            output_file='custom_report.md',
            verbose=True
        )
    
    @patch('breachpilot.cli.BreachPilotCrew')
    def test_cli_execution_error(self, mock_crew_class):
        """Test CLI handling of execution errors."""
        # Mock the crew to raise an exception
        mock_crew = MagicMock()
        mock_crew.run.side_effect = Exception("Test error")
        mock_crew_class.return_value = mock_crew
        
        result = self.runner.invoke(main, ['--target', '192.168.1.1'])
        
        assert result.exit_code == 1
        assert "Error" in result.output
    
    @patch('breachpilot.cli.BreachPilotCrew')
    def test_cli_keyboard_interrupt(self, mock_crew_class):
        """Test CLI handling of keyboard interrupt."""
        # Mock the crew to raise KeyboardInterrupt
        mock_crew = MagicMock()
        mock_crew.run.side_effect = KeyboardInterrupt()
        mock_crew_class.return_value = mock_crew
        
        result = self.runner.invoke(main, ['--target', '192.168.1.1'])
        
        assert result.exit_code == 1
        assert "interrupted" in result.output