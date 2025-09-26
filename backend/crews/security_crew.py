#!/usr/bin/env python3
"""
Professional Security Assessment CrewAI Implementation
Based on CrewAI official documentation and enterprise security best practices
"""

import os
import json
import logging
import yaml
from typing import Dict, Any, List, Optional
from pathlib import Path

from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

try:
    from crewai.tools import SerperDevTool
except ImportError:
    SerperDevTool = None

from backend.models import AnalystResult, CVEInfo, NmapResult
from backend.config import config
from .utils.cve_processor import CVEProcessor
from .utils.target_analyzer import TargetAnalyzer

# Configure logging
logger = logging.getLogger(__name__)

class SecurityAssessmentCrew:
    """
    Professional Security Assessment CrewAI implementation
    Follows CrewAI best practices with YAML configuration
    """
    
    def __init__(self):
        """
        Initialize the SecurityAssessmentCrew with agents and tasks from YAML configuration
        """
        try:
            # Initialize LLM
            self.llm = ChatOpenAI(
                model=config.LLM_MODEL or "gpt-4",
                temperature=config.LLM_TEMPERATURE or 0.1,
                api_key=config.OPENAI_API_KEY
            )
            
            # Load YAML configurations
            self.agents_config = self._load_yaml_config('agents.yaml')
            self.tasks_config = self._load_yaml_config('tasks.yaml')
            
            # Initialize utility classes
            self.cve_processor = CVEProcessor()
            self.target_analyzer = TargetAnalyzer()
            
            # Initialize tools
            self.search_tool = None
            if SerperDevTool and config.SERPER_API_KEY:
                try:
                    self.search_tool = SerperDevTool(api_key=config.SERPER_API_KEY)
                except Exception as e:
                    logger.warning(f"Failed to initialize SerperDevTool: {e}")
            
            # Create agents from YAML config
            self.agents = self._create_agents_from_config()
            
            # Crew availability flag
            self.crew_available = True
            
            logger.info("SecurityAssessmentCrew initialized successfully with YAML configuration")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityAssessmentCrew: {e}")
            self.crew_available = False
            raise
    
    def _load_yaml_config(self, filename: str) -> Dict[str, Any]:
        """
        Load YAML configuration file
        
        Args:
            filename: Name of the YAML file to load
            
        Returns:
            Parsed YAML configuration as dictionary
        """
        config_path = Path(__file__).parent.parent / filename
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    
    def _create_agents_from_config(self) -> Dict[str, Agent]:
        """
        Create CrewAI agents from YAML configuration
        
        Returns:
            Dictionary of initialized agents
        """
        agents = {}
        
        for agent_name, agent_config in self.agents_config.items():
            # Prepare tools for specific agents
            agent_tools = []
            
            # Add search tool to vulnerability hunter if available
            if agent_name == 'vulnerability_hunter' and self.search_tool:
                agent_tools.append(self.search_tool)
            
            # Create agent with YAML configuration
            agents[agent_name] = Agent(
                role=agent_config['role'],
                goal=agent_config['goal'],
                backstory=agent_config['backstory'],
                verbose=agent_config.get('verbose', True),
                allow_delegation=agent_config.get('allow_delegation', False),
                llm=self.llm,
                tools=agent_tools,
                max_iter=agent_config.get('max_iter', 3),
                memory=agent_config.get('memory', True)
            )
            
            logger.debug(f"Created agent: {agent_name} - {agent_config['role']}")
        
        return agents
    
    def _create_tasks_from_config(self, target_data: Dict[str, Any]) -> List[Task]:
        """
        Create CrewAI tasks from YAML configuration with target-specific data
        
        Args:
            target_data: Dictionary containing target system information
            
        Returns:
            List of configured tasks with context relationships
        """
        tasks = []
        task_objects = {}
        
        for task_name, task_config in self.tasks_config.items():
            # Format description with target data
            description = task_config['description'].format(**target_data)
            
            # Get agent for this task
            agent_name = task_config['agent']
            if agent_name not in self.agents:
                logger.error(f"Agent '{agent_name}' not found for task '{task_name}'")
                continue
            
            # Create task
            task = Task(
                description=description,
                expected_output=task_config['expected_output'],
                agent=self.agents[agent_name]
            )
            
            task_objects[task_name] = task
            tasks.append(task)
            logger.debug(f"Created task: {task_name} for agent: {agent_name}")
        
        # Set up context relationships after all tasks are created
        for task_name, task_config in self.tasks_config.items():
            if 'context' in task_config and task_name in task_objects:
                context_tasks = []
                for context_task_name in task_config['context']:
                    if context_task_name in task_objects:
                        context_tasks.append(task_objects[context_task_name])
                if context_tasks:
                    task_objects[task_name].context = context_tasks
                    logger.debug(f"Set context for {task_name}: {task_config['context']}")
        
        return tasks
    
    def analyze_target(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Perform comprehensive security analysis using CrewAI
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Comprehensive analyst result
        """
        logger.info(f"Starting CrewAI security assessment for {target_ip}")
        
        if not self.crew_available:
            logger.error("CrewAI not available, cannot perform analysis")
            return self._create_fallback_result(target_ip, nmap_result)
        
        try:
            # Prepare target data for task configuration
            target_data = self.target_analyzer.prepare_target_data(target_ip, nmap_result)
            
            # Create tasks with target-specific data
            tasks = self._create_tasks_from_config(target_data)
            
            if not tasks:
                logger.error("No tasks created, falling back to basic analysis")
                return self._create_fallback_result(target_ip, nmap_result)
            
            # Create and configure crew with official CrewAI structure
            crew = Crew(
                agents=list(self.agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=True,
                memory=config.CREWAI_MEMORY_ENABLED,
                full_output=True,  # Get detailed output from all agents
                share_crew=False   # Don't share crew data externally
            )
            
            logger.info(f"Executing CrewAI crew with {len(tasks)} tasks and {len(self.agents)} agents")
            
            # Execute the crew
            crew_result = crew.kickoff()
            
            # Process results into structured format
            analyst_result = self.cve_processor.process_crew_results(
                crew_result, target_ip, nmap_result
            )
            
            logger.info(f"CrewAI analysis completed successfully for {target_ip}")
            return analyst_result
            
        except Exception as e:
            logger.error(f"CrewAI analysis failed: {e}", exc_info=True)
            return self._create_fallback_result(target_ip, nmap_result)
    
    def _create_fallback_result(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Create fallback result when CrewAI is not available
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Basic analyst result
        """
        logger.warning("Creating fallback analysis result - CrewAI not available")
        return self.cve_processor.create_fallback_result(target_ip, nmap_result)
    
    def get_crew_status(self) -> Dict[str, Any]:
        """
        Get status of CrewAI components
        
        Returns:
            Status dictionary
        """
        return {
            "crew_available": self.crew_available,
            "agents_count": len(self.agents) if hasattr(self, 'agents') else 0,
            "llm_model": config.LLM_MODEL,
            "temperature": config.LLM_TEMPERATURE,
            "serper_configured": bool(self.search_tool),
            "memory_enabled": config.CREWAI_MEMORY_ENABLED,
            "agents_loaded": list(self.agents.keys()) if hasattr(self, 'agents') else [],
            "tasks_loaded": list(self.tasks_config.keys()) if hasattr(self, 'tasks_config') else []
        }
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate the CrewAI configuration
        
        Returns:
            Validation results
        """
        validation = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Check OpenAI API key
            if not config.OPENAI_API_KEY:
                validation["errors"].append("OpenAI API key not configured")
                validation["valid"] = False
            
            # Check agents configuration
            if not self.agents_config:
                validation["errors"].append("No agents configuration loaded")
                validation["valid"] = False
            
            # Check tasks configuration
            if not self.tasks_config:
                validation["errors"].append("No tasks configuration loaded")
                validation["valid"] = False
            
            # Check agent-task mappings
            for task_name, task_config in self.tasks_config.items():
                agent_name = task_config.get('agent')
                if agent_name and agent_name not in self.agents_config:
                    validation["errors"].append(
                        f"Task '{task_name}' references unknown agent '{agent_name}'"
                    )
                    validation["valid"] = False
            
            # Warnings
            if not self.search_tool:
                validation["warnings"].append(
                    "Serper API not configured - web search capabilities limited"
                )
            
        except Exception as e:
            validation["errors"].append(f"Validation error: {str(e)}")
            validation["valid"] = False
        
        return validation
