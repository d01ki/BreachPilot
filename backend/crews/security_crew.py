#!/usr/bin/env python3
"""
Professional Security Assessment CrewAI Implementation
Based on CrewAI official documentation and enterprise security best practices
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from crewai import Agent, Task, Crew, Process
from crewai.tools import SerperDevTool, WebsiteSearchTool, FileReadTool
from langchain_openai import ChatOpenAI
import yaml

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
            self.llm = ChatOpenAI(
                model=config.LLM_MODEL or "gpt-4",
                temperature=config.LLM_TEMPERATURE or 0.1,
                api_key=config.OPENAI_API_KEY
            )
            
            # Load configuration files
            self.agents_config = self._load_yaml_config('agents.yaml')
            self.tasks_config = self._load_yaml_config('tasks.yaml')
            
            # Initialize utility classes
            self.cve_processor = CVEProcessor()
            self.target_analyzer = TargetAnalyzer()
            
            # Initialize tools
            self.search_tool = SerperDevTool(api_key=config.SERPER_API_KEY) if config.SERPER_API_KEY else None
            self.web_search_tool = WebsiteSearchTool()
            self.file_tool = FileReadTool()
            
            # Create agents
            self.agents = self._create_agents()
            
            # Crew availability flag
            self.crew_available = True
            
            logger.info("SecurityAssessmentCrew initialized successfully with CrewAI YAML configuration")
            
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
    
    def _create_agents(self) -> Dict[str, Agent]:
        """
        Create CrewAI agents from YAML configuration
        
        Returns:
            Dictionary of initialized agents
        """
        agents = {}
        
        for agent_name, agent_config in self.agents_config.items():
            # Prepare tools for specific agents
            agent_tools = []
            
            # Add tools based on agent role
            if agent_name == 'vulnerability_hunter' and self.search_tool:
                agent_tools.append(self.search_tool)
            if agent_name == 'cve_researcher':
                agent_tools.extend([self.web_search_tool, self.file_tool])
            
            # Create agent
            agents[agent_name] = Agent(
                role=agent_config['role'],
                goal=agent_config['goal'],
                backstory=agent_config['backstory'],
                verbose=agent_config.get('verbose', True),
                allow_delegation=agent_config.get('allow_delegation', False),
                llm=self.llm,
                tools=agent_tools
            )
            
            logger.debug(f"Created agent: {agent_name} - {agent_config['role']}")
        
        return agents
    
    def _create_tasks(self, target_data: Dict[str, Any]) -> List[Task]:
        """
        Create CrewAI tasks from YAML configuration with target-specific data
        
        Args:
            target_data: Dictionary containing target system information
            
        Returns:
            List of configured tasks
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
        
        # Set up context relationships
        for task_name, task_config in self.tasks_config.items():
            if 'context' in task_config and task_name in task_objects:
                context_tasks = []
                for context_task_name in task_config['context']:
                    if context_task_name in task_objects:
                        context_tasks.append(task_objects[context_task_name])
                if context_tasks:
                    task_objects[task_name].context = context_tasks
        
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
            tasks = self._create_tasks(target_data)
            
            if not tasks:
                logger.error("No tasks created, falling back to basic analysis")
                return self._create_fallback_result(target_ip, nmap_result)
            
            # Create and configure crew
            crew = Crew(
                agents=list(self.agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=True,
                memory=True,  # Enable memory for better context sharing
                embedder={
                    "provider": "openai",
                    "config": {
                        "model": "text-embedding-3-small"
                    }
                }
            )
            
            logger.info(f"Executing CrewAI crew with {len(tasks)} tasks and {len(self.agents)} agents")
            
            # Execute the crew
            crew_result = crew.kickoff()
            
            # Process results into structured format
            analyst_result = self.cve_processor.process_crew_results(crew_result, target_ip, nmap_result)
            
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
