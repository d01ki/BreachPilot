import json
import re
import requests
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from backend.models import PoCResult, PoCInfo, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class PoCCrew:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=config.LLM_MODEL,
            temperature=0.3,
            api_key=config.OPENAI_API_KEY
        )
    
    def search_pocs(self, selected_cves: List[str], limit: int = 3) -> List[PoCResult]:
        """Search for PoC exploits for selected CVEs"""
        logger.info(f"Searching PoCs for: {selected_cves}")
        results = []
        
        for cve_id in selected_cves:
            logger.info(f"Searching PoCs for {cve_id}...")
            pocs = self._search_single_cve(cve_id, limit)
            
            result = PoCResult(
                cve_id=cve_id,
                status=StepStatus.COMPLETED if pocs else StepStatus.FAILED,
                available_pocs=pocs
            )
            
            if pocs:
                logger.info(f"  Found {len(pocs)} PoCs for {cve_id}")
            else:
                logger.warning(f"  No PoCs found for {cve_id}")
            
            results.append(result)
        
        return results
    
    def _search_single_cve(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search for PoCs from multiple sources"""
        pocs = []
        
        # Search GitHub
        github_pocs = self._search_github(cve_id, limit)
        pocs.extend(github_pocs)
        
        # Search ExploitDB
        exploitdb_pocs = self._search_exploitdb(cve_id, limit)
        pocs.extend(exploitdb_pocs)
        
        # Search Packet Storm
        packetstorm_pocs = self._search_packetstorm(cve_id, limit)
        pocs.extend(packetstorm_pocs)
        
        # Deduplicate and limit
        unique_pocs = {}
        for poc in pocs:
            if poc.url not in unique_pocs:
                unique_pocs[poc.url] = poc
        
        return list(unique_pocs.values())[:limit]
    
    def _search_github(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub for PoCs"""
        pocs = []
        try:
            # GitHub API search
            headers = {'Accept': 'application/vnd.github.v3+json'}
            if config.GITHUB_TOKEN:
                headers['Authorization'] = f'token {config.GITHUB_TOKEN}'
            
            query = f'{cve_id} PoC OR exploit'
            url = f'https://api.github.com/search/repositories?q={query}&sort=stars&order=desc'
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('items', [])[:limit]:
                    # Try to get exploit code from repo
                    code = self._fetch_exploit_code_from_repo(item['full_name'], cve_id)
                    
                    poc = PoCInfo(
                        source='GitHub',
                        url=item['html_url'],
                        description=item.get('description', ''),
                        author=item['owner']['login'],
                        stars=item.get('stargazers_count', 0),
                        code=code
                    )
                    pocs.append(poc)
                    logger.info(f"    GitHub: {item['full_name']} ({poc.stars} stars)")
        
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")
        
        return pocs
    
    def _fetch_exploit_code_from_repo(self, repo_name: str, cve_id: str) -> str:
        """Fetch exploit code from GitHub repo"""
        try:
            # Search for exploit files in repo
            api_url = f'https://api.github.com/repos/{repo_name}/contents'
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                files = response.json()
                
                # Look for exploit files (.py, .sh, .rb, etc.)
                for file_info in files:
                    if isinstance(file_info, dict):
                        name = file_info.get('name', '').lower()
                        if any(ext in name for ext in ['.py', '.sh', '.rb', '.pl', 'exploit', 'poc']):
                            # Download file content
                            download_url = file_info.get('download_url')
                            if download_url:
                                code_response = requests.get(download_url, timeout=10)
                                if code_response.status_code == 200:
                                    return code_response.text[:5000]  # Limit to 5000 chars
        except:
            pass
        
        return ""
    
    def _search_exploitdb(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search ExploitDB"""
        pocs = []
        try:
            # Search ExploitDB using Google (since they don't have an API)
            search_query = f'site:exploit-db.com {cve_id}'
            url = f'https://www.google.com/search?q={search_query}'
            
            # Simple scraping (in production, use official API or database)
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Parse response for ExploitDB links
                exploitdb_links = re.findall(r'https://www\.exploit-db\.com/exploits/(\d+)', response.text)
                
                for exploit_id in exploitdb_links[:limit]:
                    exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
                    raw_url = f'https://www.exploit-db.com/raw/{exploit_id}'
                    
                    # Try to fetch exploit code
                    code = ""
                    try:
                        code_response = requests.get(raw_url, timeout=10)
                        if code_response.status_code == 200:
                            code = code_response.text[:5000]
                    except:
                        pass
                    
                    poc = PoCInfo(
                        source='ExploitDB',
                        url=exploit_url,
                        description=f'ExploitDB #{exploit_id}',
                        author='ExploitDB',
                        code=code
                    )
                    pocs.append(poc)
                    logger.info(f"    ExploitDB: {exploit_id}")
        
        except Exception as e:
            logger.warning(f"ExploitDB search failed: {e}")
        
        return pocs
    
    def _search_packetstorm(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search Packet Storm"""
        pocs = []
        try:
            url = f'https://packetstormsecurity.com/search/?q={cve_id}'
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Parse for exploit links
                links = re.findall(r'href="(/files/[^"]+)"', response.text)
                
                for link in links[:limit]:
                    full_url = f'https://packetstormsecurity.com{link}'
                    poc = PoCInfo(
                        source='PacketStorm',
                        url=full_url,
                        description='PacketStorm Security',
                        author='PacketStorm'
                    )
                    pocs.append(poc)
                    logger.info(f"    PacketStorm: {link}")
        
        except Exception as e:
            logger.warning(f"PacketStorm search failed: {e}")
        
        return pocs
