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
        """Search for specific PoC exploits prioritizing exact CVE matches"""
        logger.info(f"Searching precise CVE-specific PoCs for {len(selected_cves)} CVEs (limit: {limit} per CVE)")
        results = []
        
        for cve_id in selected_cves:
            pocs = self._search_single_cve_precise(cve_id, limit)
            
            result = PoCResult(
                cve_id=cve_id,
                status=StepStatus.COMPLETED if pocs else StepStatus.FAILED,
                available_pocs=pocs
            )
            
            github_count = len([p for p in pocs if 'github.com' in p.url])
            logger.info(f"Found {len(pocs)} precise PoCs for {cve_id} ({github_count} GitHub repos)")
            results.append(result)
        
        return results
    
    def _search_single_cve_precise(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search for PoCs with precise CVE matching to avoid generic repos"""
        all_pocs = []
        
        # Primary search: Specific GitHub repositories for exact CVE
        github_repos = self._search_github_repositories_precise(cve_id, limit)
        all_pocs.extend(github_repos)
        
        # Secondary search: ExploitDB (usually has precise CVE matches)
        if len(all_pocs) < limit:
            exploitdb_pocs = self._search_exploitdb(cve_id, limit - len(all_pocs))
            all_pocs.extend(exploitdb_pocs)
        
        # Tertiary search: GitHub code files (only if very specific)
        if len(all_pocs) < limit:
            github_files = self._search_github_code_files_precise(cve_id, limit - len(all_pocs))
            all_pocs.extend(github_files)
        
        # Filter and deduplicate
        unique_pocs = self._deduplicate_and_filter_quality(all_pocs, cve_id)
        
        return unique_pocs[:limit]
    
    def _search_github_repositories_precise(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub repositories with precise CVE matching"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Very specific search queries to avoid generic repos
            search_queries = [
                f'"{cve_id}" in:name',  # CVE in repository name (most precise)
                f'"{cve_id}" PoC in:name,description',  # CVE + PoC in name/description
                f'"{cve_id}" exploit in:name,description',  # CVE + exploit
                f'"{cve_id}" proof concept',  # CVE + proof of concept
            ]
            
            seen_repos = set()
            
            for query in search_queries:
                if len(pocs) >= limit * 2:  # Get extra for quality filtering
                    break
                
                try:
                    # Search repositories with precise matching
                    url = f'https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page=10'
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
                            
                            # Strict quality filtering
                            repo_score = self._calculate_repo_score_strict(item, cve_id)
                            
                            # Only include highly relevant repositories
                            if repo_score >= 50:  # Higher threshold
                                poc = PoCInfo(
                                    source='GitHub Repository',
                                    url=item['html_url'],
                                    description=self._clean_description(item.get('description', f'GitHub repository for {cve_id}')),
                                    author=item['owner']['login'],
                                    stars=item.get('stargazers_count', 0),
                                    code="",  # Will be cloned, not copied
                                    repo_score=repo_score  # For prioritization
                                )
                                pocs.append(poc)
                                logger.debug(f"  Added repo: {repo_name} (score: {repo_score})")
                            else:
                                logger.debug(f"  Rejected repo: {repo_name} (score: {repo_score})")
                                
                except Exception as e:
                    logger.debug(f"GitHub repo search query '{query}' failed: {e}")
                    continue
            
        except Exception as e:
            logger.warning(f"GitHub repository search failed: {e}")
        
        return pocs
    
    def _calculate_repo_score_strict(self, repo_item: Dict, cve_id: str) -> int:
        """Calculate repository relevance score with strict filtering"""
        score = 0
        
        name = repo_item.get('name', '').lower()
        description = repo_item.get('description', '').lower()
        full_name = repo_item.get('full_name', '').lower()
        
        # MANDATORY: Must have CVE ID mentioned
        cve_mentioned = (cve_id.lower() in name or 
                        cve_id.lower() in description or
                        cve_id.lower() in full_name)
        
        if not cve_mentioned:
            return -100  # Immediate rejection
        
        # Very high priority: CVE in repository name
        if cve_id.lower() in name:
            score += 200
        
        # High priority: CVE in description
        if cve_id.lower() in description:
            score += 100
        
        # Medium priority: PoC/exploit keywords in name
        if any(keyword in name for keyword in ['poc', 'exploit', 'cve', 'vulnerability']):
            score += 50
        else:
            score -= 20  # Penalize non-exploit repos
        
        # Stars bonus (but limited)
        stars = repo_item.get('stargazers_count', 0)
        score += min(stars * 2, 30)  # Max 30 points from stars
        
        # Recent activity bonus
        updated_at = repo_item.get('updated_at', '')
        if '2024' in updated_at or '2023' in updated_at:
            score += 20
        elif '2022' in updated_at or '2021' in updated_at:
            score += 10
        else:
            score -= 10  # Penalize very old repos
        
        # Language bonus
        language = repo_item.get('language', '').lower()
        if language in ['python', 'shell', 'c', 'c++', 'go']:
            score += 15
        
        # MAJOR PENALTIES for generic repos
        blacklist_patterns = [
            'awesome', 'list', 'collection', 'paper', 'research',
            'vulnerability-database', 'cve-database', 'security-tools',
            'penetration-testing', 'pentest', 'toolkit', 'framework',
            'scanner', 'fuzzer', 'multiple', 'various', 'general'
        ]
        
        for pattern in blacklist_patterns:
            if pattern in full_name or pattern in name or pattern in description:
                score -= 100  # Heavy penalty
                logger.debug(f"  Penalized for blacklist pattern: {pattern}")
        
        # Bonus for specific CVE-focused repos
        if len(name.split('-')) <= 3 and cve_id.lower() in name:
            score += 50  # Bonus for focused repos
        
        return score
    
    def _search_github_code_files_precise(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub code files with precise CVE matching"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Very specific code search queries
            code_queries = [
                f'"{cve_id}" extension:py filename:exploit',
                f'"{cve_id}" extension:py filename:poc',
                f'"{cve_id}" extension:sh',
                f'"{cve_id}" extension:c filename:exploit'
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
                            
                            # Only include if repository name is reasonable
                            repo_name = item['repository']['full_name'].lower()
                            if not any(bad in repo_name for bad in ['penetration-testing', 'toolkit', 'collection']):
                                poc = PoCInfo(
                                    source='GitHub Code',
                                    url=file_url,
                                    description=f'{cve_id} exploit: {item["name"]} in {item["repository"]["full_name"]}',
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
    
    def _search_exploitdb(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search ExploitDB for precise CVE matches"""
        pocs = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # More specific ExploitDB search
            search_url = f'https://www.exploit-db.com/search?cve={cve_id}&type=remote'
            response = requests.get(search_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse HTML for exploit IDs more precisely
                exploit_pattern = rf'/exploits/(\d+)[^"]*.*{cve_id}'
                exploit_ids = re.findall(r'/exploits/(\d+)', response.text)
                
                # Verify CVE is mentioned in the page content
                verified_ids = []
                for exploit_id in exploit_ids[:limit * 2]:  # Check more than needed
                    if cve_id in response.text:  # Basic verification
                        verified_ids.append(exploit_id)
                    if len(verified_ids) >= limit:
                        break
                
                for exploit_id in verified_ids:
                    exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
                    
                    poc = PoCInfo(
                        source='ExploitDB',
                        url=exploit_url,
                        description=f'ExploitDB #{exploit_id} - {cve_id} exploit',
                        author='ExploitDB Community',
                        stars=0,
                        code=""  # Will be fetched if needed
                    )
                    pocs.append(poc)
            
        except Exception as e:
            logger.debug(f"ExploitDB search error: {e}")
        
        return pocs
    
    def _clean_description(self, description: str) -> str:
        """Clean and validate description"""
        if not description:
            return "PoC exploit repository"
        
        # Remove excessive Chinese characters or weird descriptions
        if len(re.findall(r'[\u4e00-\u9fff]', description)) > len(description) * 0.3:
            return "PoC exploit repository"
        
        # Remove very long descriptions
        if len(description) > 200:
            description = description[:200] + "..."
        
        return description
    
    def _deduplicate_and_filter_quality(self, pocs: List[PoCInfo], cve_id: str) -> List[PoCInfo]:
        """Remove duplicates and filter for quality"""
        # Remove duplicates by URL
        unique_pocs = {}
        for poc in pocs:
            if poc.url not in unique_pocs:
                unique_pocs[poc.url] = poc
        
        # Filter for quality
        quality_filtered = []
        for poc in unique_pocs.values():
            # Additional quality checks
            if self._is_quality_poc(poc, cve_id):
                quality_filtered.append(poc)
            else:
                logger.debug(f"  Filtered out low-quality PoC: {poc.url}")
        
        # Prioritization scoring
        def priority_score(poc: PoCInfo) -> tuple:
            source_priority = {
                'GitHub Repository': 1000,
                'ExploitDB': 900,
                'GitHub Code': 800
            }
            
            base_score = source_priority.get(poc.source, 0)
            
            # Add repo score if available
            if hasattr(poc, 'repo_score'):
                base_score += poc.repo_score
            
            # CVE in URL or description bonus
            if cve_id.lower() in poc.url.lower() or cve_id.lower() in poc.description.lower():
                base_score += 100
            
            return (base_score, poc.stars, poc.source)
        
        # Sort by priority (highest first)
        sorted_pocs = sorted(quality_filtered, key=priority_score, reverse=True)
        
        return sorted_pocs
    
    def _is_quality_poc(self, poc: PoCInfo, cve_id: str) -> bool:
        """Check if PoC is of sufficient quality"""
        url_lower = poc.url.lower()
        desc_lower = poc.description.lower()
        
        # Must contain CVE ID
        if cve_id.lower() not in url_lower and cve_id.lower() not in desc_lower:
            return False
        
        # Blacklist generic repositories
        blacklist = [
            'penetration-testing', 'pentest-tool', 'security-tool',
            'vulnerability-scanner', 'exploit-collection', 'awesome-',
            'hacking-tool', 'security-research', 'red-team'
        ]
        
        for term in blacklist:
            if term in url_lower or term in desc_lower:
                return False
        
        # Must be somewhat specific
        if 'various' in desc_lower or 'multiple' in desc_lower or 'collection' in desc_lower:
            return False
        
        return True
