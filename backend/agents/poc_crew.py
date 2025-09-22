import json
import re
import requests
import os
from typing import List, Dict, Any
from backend.models import PoCResult, PoCInfo, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class PoCCrew:
    def __init__(self):
        pass
    
    def search_pocs(self, selected_cves: List[str], limit: int = 4) -> List[PoCResult]:
        """Search for PoC exploits prioritizing GitHub repositories for git clone"""
        logger.info(f"Searching GitHub-focused PoCs for {len(selected_cves)} CVEs (limit: {limit} per CVE)")
        results = []
        
        for cve_id in selected_cves:
            pocs = self._search_single_cve_github_focused(cve_id, limit)
            
            result = PoCResult(
                cve_id=cve_id,
                status=StepStatus.COMPLETED if pocs else StepStatus.FAILED,
                available_pocs=pocs
            )
            
            github_count = len([p for p in pocs if 'github.com' in p.url])
            logger.info(f"Found {len(pocs)} PoCs for {cve_id} ({github_count} GitHub repos)")
            results.append(result)
        
        return results
    
    def _search_single_cve_github_focused(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search for PoCs with focus on GitHub repositories"""
        all_pocs = []
        
        # Primary search: GitHub repositories (for git clone)
        github_repos = self._search_github_repositories(cve_id, limit)
        all_pocs.extend(github_repos)
        
        # Secondary search: GitHub code files (as backup)
        if len(github_repos) < limit:
            github_files = self._search_github_code_files(cve_id, limit - len(github_repos))
            all_pocs.extend(github_files)
        
        # Tertiary search: Other sources (if still need more)
        if len(all_pocs) < limit:
            other_sources = self._search_other_sources(cve_id, limit - len(all_pocs))
            all_pocs.extend(other_sources)
        
        # Deduplicate and prioritize GitHub repos
        unique_pocs = self._deduplicate_and_prioritize(all_pocs)
        
        return unique_pocs[:limit]
    
    def _search_github_repositories(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub repositories (highest priority for git clone)"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Repository search queries optimized for PoC repositories
            search_queries = [
                f'{cve_id} PoC',
                f'{cve_id} exploit',
                f'{cve_id} proof concept',
                f'"{cve_id}" vulnerability',
                f'{cve_id.replace("-", "_")} exploit'
            ]
            
            seen_repos = set()
            
            for query in search_queries:
                if len(pocs) >= limit * 2:  # Get extra for quality filtering
                    break
                
                try:
                    # Search repositories specifically
                    url = f'https://api.github.com/search/repositories?q={query} in:name,description,readme&sort=stars&order=desc&per_page=10'
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        for item in data.get('items', []):
                            if len(pocs) >= limit * 2:
                                break
                            
                            repo_name = item['full_name']
                            if repo_name in seen_repos:
                                continue
                            seen_repos.add(repo_name)
                            
                            # Prioritize repositories with specific characteristics
                            repo_score = self._calculate_repo_score(item, cve_id)
                            
                            if repo_score > 0:  # Only include relevant repositories
                                poc = PoCInfo(
                                    source='GitHub Repository',
                                    url=item['html_url'],
                                    description=item.get('description', f'GitHub repository for {cve_id}'),
                                    author=item['owner']['login'],
                                    stars=item.get('stargazers_count', 0),
                                    code="",  # Will be cloned, not copied
                                    repo_score=repo_score  # For prioritization
                                )
                                pocs.append(poc)
                                
                except Exception as e:
                    logger.debug(f"GitHub repo search query '{query}' failed: {e}")
                    continue
            
        except Exception as e:
            logger.warning(f"GitHub repository search failed: {e}")
        
        return pocs
    
    def _calculate_repo_score(self, repo_item: Dict, cve_id: str) -> int:
        """Calculate repository relevance score"""
        score = 0
        
        name = repo_item.get('name', '').lower()
        description = repo_item.get('description', '').lower()
        full_name = repo_item.get('full_name', '').lower()
        
        # High priority: CVE mentioned in name
        if cve_id.lower() in name:
            score += 100
        
        # High priority: CVE mentioned in description
        if cve_id.lower() in description:
            score += 80
        
        # Medium priority: exploit/poc keywords in name
        if any(keyword in name for keyword in ['exploit', 'poc', 'cve', 'vuln']):
            score += 50
        
        # Medium priority: exploit/poc keywords in description
        if any(keyword in description for keyword in ['exploit', 'poc', 'proof', 'vulnerability']):
            score += 30
        
        # Stars bonus (up to 20 points)
        stars = repo_item.get('stargazers_count', 0)
        score += min(stars, 20)
        
        # Recent activity bonus
        updated_at = repo_item.get('updated_at', '')
        if updated_at and '2024' in updated_at or '2023' in updated_at:
            score += 10
        
        # Language bonus (Python/Shell preferred for exploits)
        language = repo_item.get('language', '').lower()
        if language in ['python', 'shell', 'c', 'c++']:
            score += 15
        
        # Penalty for non-exploit repositories
        if any(keyword in full_name for keyword in ['awesome', 'list', 'collection', 'paper']):
            score -= 50
        
        # Penalty for very old repositories
        if updated_at and '2020' in updated_at or '2019' in updated_at:
            score -= 10
        
        return score
    
    def _search_github_code_files(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub code files (secondary priority)"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Code search for specific file types
            code_queries = [
                f'{cve_id} extension:py',
                f'{cve_id} extension:sh',
                f'{cve_id} extension:c',
                f'"{cve_id}" filename:exploit'
            ]
            
            seen_files = set()
            
            for query in code_queries:
                if len(pocs) >= limit:
                    break
                    
                try:
                    url = f'https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=5'
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        for item in data.get('items', []):
                            if len(pocs) >= limit:
                                break
                            
                            file_url = item['html_url']
                            if file_url in seen_files:
                                continue
                            seen_files.add(file_url)
                            
                            poc = PoCInfo(
                                source='GitHub Code',
                                url=file_url,
                                description=f'Exploit code: {item["name"]} in {item["repository"]["full_name"]}',
                                author=item['repository']['owner']['login'],
                                stars=item['repository'].get('stargazers_count', 0),
                                code=""  # Will be fetched if needed
                            )
                            pocs.append(poc)
                            
                except Exception as e:
                    logger.debug(f"GitHub code search failed: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"GitHub code search failed: {e}")
        
        return pocs
    
    def _search_other_sources(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search other sources as fallback"""
        pocs = []
        
        # Search ExploitDB
        try:
            exploitdb_pocs = self._search_exploitdb(cve_id, limit)
            pocs.extend(exploitdb_pocs)
        except Exception as e:
            logger.debug(f"ExploitDB search failed: {e}")
        
        # Search PacketStorm if still need more
        if len(pocs) < limit:
            try:
                packetstorm_pocs = self._search_packetstorm(cve_id, limit - len(pocs))
                pocs.extend(packetstorm_pocs)
            except Exception as e:
                logger.debug(f"PacketStorm search failed: {e}")
        
        return pocs
    
    def _search_exploitdb(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search ExploitDB"""
        pocs = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            search_url = f'https://www.exploit-db.com/search?cve={cve_id}'
            response = requests.get(search_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse HTML for exploit IDs
                exploit_ids = re.findall(r'/exploits/(\d+)', response.text)
                unique_ids = list(dict.fromkeys(exploit_ids))  # Remove duplicates, preserve order
                
                for exploit_id in unique_ids[:limit]:
                    exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
                    
                    poc = PoCInfo(
                        source='ExploitDB',
                        url=exploit_url,
                        description=f'ExploitDB #{exploit_id} for {cve_id}',
                        author='ExploitDB',
                        code=""  # Will be fetched if needed
                    )
                    pocs.append(poc)
            
        except Exception as e:
            logger.debug(f"ExploitDB search error: {e}")
        
        return pocs
    
    def _search_packetstorm(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search PacketStorm"""
        pocs = []
        try:
            url = f'https://packetstormsecurity.com/search/?q={cve_id}'
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse for exploit links
                links = re.findall(r'href="(/files/[^"]+)"', response.text)
                
                for link in links[:limit]:
                    full_url = f'https://packetstormsecurity.com{link}'
                    
                    poc = PoCInfo(
                        source='PacketStorm',
                        url=full_url,
                        description=f'PacketStorm Security - {link.split("/")[-1]}',
                        author='PacketStorm',
                        code=""
                    )
                    pocs.append(poc)
        
        except Exception as e:
            logger.debug(f"PacketStorm search error: {e}")
        
        return pocs
    
    def _deduplicate_and_prioritize(self, pocs: List[PoCInfo]) -> List[PoCInfo]:
        """Remove duplicates and prioritize by source and quality"""
        # Remove duplicates by URL
        unique_pocs = {}
        for poc in pocs:
            if poc.url not in unique_pocs:
                unique_pocs[poc.url] = poc
        
        # Prioritization scoring
        def priority_score(poc: PoCInfo) -> tuple:
            source_priority = {
                'GitHub Repository': 1000,  # Highest priority for git clone
                'GitHub Code': 800,
                'ExploitDB': 600,
                'PacketStorm': 400
            }
            
            base_score = source_priority.get(poc.source, 0)
            
            # Add repo score if available
            if hasattr(poc, 'repo_score'):
                base_score += poc.repo_score
            
            # Add stars bonus
            stars_bonus = min(poc.stars * 2, 100) if poc.stars else 0
            
            return (base_score + stars_bonus, poc.stars, poc.source)
        
        # Sort by priority (highest first)
        sorted_pocs = sorted(unique_pocs.values(), key=priority_score, reverse=True)
        
        return sorted_pocs
