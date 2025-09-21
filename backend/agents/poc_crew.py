import json
import requests
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from backend.models import PoCResult, CVEAnalysis, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class PoCCrew:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=config.LLM_MODEL,
            temperature=config.LLM_TEMPERATURE,
            api_key=config.OPENAI_API_KEY
        )
    
    def search_poc(self, cve_analysis: CVEAnalysis) -> PoCResult:
        """Search for PoC exploits"""
        logger.info(f"Searching PoC for {cve_analysis.cve_id}")
        
        result = PoCResult(
            cve_id=cve_analysis.cve_id,
            status=StepStatus.RUNNING
        )
        
        try:
            # Search multiple sources
            sources = self._search_exploit_sources(cve_analysis.cve_id)
            result.poc_sources = sources
            
            if sources:
                # Use agent to select best PoC
                result.selected_poc = self._select_best_poc(cve_analysis, sources)
                result.status = StepStatus.COMPLETED
            else:
                logger.warning(f"No PoC found for {cve_analysis.cve_id}")
                result.status = StepStatus.FAILED
            
        except Exception as e:
            logger.error(f"PoC search failed: {e}")
            result.status = StepStatus.FAILED
        
        # Save result
        self._save_result(cve_analysis.cve_id, result)
        return result
    
    def _search_exploit_sources(self, cve_id: str) -> List[Dict[str, str]]:
        """Search various exploit databases"""
        sources = []
        
        # Search Exploit-DB
        exploitdb_results = self._search_exploitdb(cve_id)
        sources.extend(exploitdb_results)
        
        # Search GitHub
        github_results = self._search_github(cve_id)
        sources.extend(github_results)
        
        # Search Metasploit modules
        msf_results = self._search_metasploit(cve_id)
        sources.extend(msf_results)
        
        return sources
    
    def _search_exploitdb(self, cve_id: str) -> List[Dict[str, str]]:
        """Search Exploit-DB"""
        results = []
        try:
            url = f"https://www.exploit-db.com/search?cve={cve_id}"
            # Note: In production, use proper API or scraping
            # This is a placeholder
            results.append({
                "source": "Exploit-DB",
                "url": url,
                "type": "web"
            })
        except Exception as e:
            logger.warning(f"Exploit-DB search failed: {e}")
        
        return results
    
    def _search_github(self, cve_id: str) -> List[Dict[str, str]]:
        """Search GitHub for PoCs"""
        results = []
        try:
            # GitHub search API
            headers = {"Accept": "application/vnd.github.v3+json"}
            url = f"https://api.github.com/search/repositories?q={cve_id}+PoC"
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', [])[:5]:  # Top 5 results
                    results.append({
                        "source": "GitHub",
                        "name": item.get('name'),
                        "url": item.get('html_url'),
                        "description": item.get('description', ''),
                        "stars": item.get('stargazers_count', 0),
                        "type": "github"
                    })
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")
        
        return results
    
    def _search_metasploit(self, cve_id: str) -> List[Dict[str, str]]:
        """Search for Metasploit modules"""
        results = []
        try:
            # Search local Metasploit database
            import subprocess
            cmd = f"msfconsole -q -x 'search {cve_id}; exit'"
            
            # Note: This requires Metasploit to be installed
            # In production, use proper Metasploit API
            results.append({
                "source": "Metasploit",
                "cve": cve_id,
                "type": "metasploit"
            })
        except Exception as e:
            logger.warning(f"Metasploit search failed: {e}")
        
        return results
    
    def _select_best_poc(self, cve_analysis: CVEAnalysis, sources: List[Dict[str, str]]) -> Dict[str, Any]:
        """Use agent to select best PoC"""
        try:
            # Create PoC selector agent
            poc_selector = Agent(
                role='Exploit Verification Specialist',
                goal='Select the most reliable and effective PoC exploit',
                backstory="""You are an expert in evaluating exploit code quality and reliability. 
                You analyze available PoCs and select the best option based on code quality, 
                reliability, and ease of use.""",
                llm=self.llm,
                verbose=True
            )
            
            # Create selection task
            sources_text = json.dumps(sources, indent=2)
            
            select_task = Task(
                description=f"""Analyze the following PoC sources for {cve_analysis.cve_id}:
                
                {sources_text}
                
                Select the best PoC based on:
                1. Source reliability (prefer official repos, high GitHub stars)
                2. Code quality indicators
                3. Recent updates
                4. Clear documentation
                
                CVE Context: {cve_analysis.description}
                Affected Service: {cve_analysis.affected_service}
                
                Recommend the best option and explain why.""",
                agent=poc_selector,
                expected_output="The selected PoC with justification"
            )
            
            crew = Crew(
                agents=[poc_selector],
                tasks=[select_task],
                process=Process.sequential,
                verbose=True
            )
            
            result = crew.kickoff()
            
            # Parse result and return selected PoC
            # In production, parse the agent's response properly
            # For now, return highest priority source
            if sources:
                return sources[0]
            
        except Exception as e:
            logger.error(f"PoC selection failed: {e}")
            if sources:
                return sources[0]
        
        return None
    
    def _save_result(self, cve_id: str, result: PoCResult):
        """Save PoC result to JSON"""
        output_file = config.DATA_DIR / f"{cve_id}_poc.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"PoC result saved to {output_file}")
