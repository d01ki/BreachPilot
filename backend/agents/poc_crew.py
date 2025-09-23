import json
import re
import requests
import os
import time
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
            temperature=0.1,  # Low temperature for precise searches
            api_key=config.OPENAI_API_KEY
        )
        logger.info("PoCCrew initialized with AI agents")
    
    def search_pocs(self, selected_cves: List[str], limit: int = 4) -> List[PoCResult]:
        """Search for PoC exploits using AI-powered intelligent agents"""
        logger.info(f"🤖 AI Agent: Searching PoCs for {len(selected_cves)} CVEs (limit: {limit} per CVE)")
        results = []
        
        for cve_id in selected_cves:
            logger.info(f"🎯 AI Agent analyzing CVE: {cve_id}")
            
            # Use AI agent to enhance PoC search
            pocs = self._ai_enhanced_poc_search(cve_id, limit)
            
            result = PoCResult(
                cve_id=cve_id,
                status=StepStatus.COMPLETED if pocs else StepStatus.FAILED,
                available_pocs=pocs,
                total_found=len(pocs),
                with_code=len([p for p in pocs if p.code and p.code.strip()]),
                search_duration=None
            )
            
            github_count = len([p for p in pocs if 'github.com' in p.url])
            logger.info(f"✅ AI Agent found {len(pocs)} quality PoCs for {cve_id} ({github_count} GitHub repos)")
            results.append(result)
        
        return results
    
    def _ai_enhanced_poc_search(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Use AI agents to intelligently search and analyze PoCs"""
        start_time = time.time()
        
        try:
            # Direct search first (faster)
            direct_results = self._direct_search_enhanced(cve_id, limit)
            
            # Enhance with code content
            enhanced_pocs = self._enhance_pocs_with_code(direct_results, cve_id)
            
            # Manual ranking
            final_pocs = self._manual_rank_pocs(enhanced_pocs, cve_id)[:limit]
            
            search_duration = round(time.time() - start_time, 2)
            logger.info(f"🎯 Enhanced search completed in {search_duration}s")
            
            return final_pocs
            
        except Exception as e:
            logger.error(f"Enhanced PoC search failed for {cve_id}: {e}")
            # Fallback to basic search
            return self._direct_search_enhanced(cve_id, limit)[:limit]
    
    def _enhance_pocs_with_code(self, pocs: List[PoCInfo], cve_id: str) -> List[PoCInfo]:
        """Enhance PoCs by fetching actual code content"""
        enhanced_pocs = []
        
        for poc in pocs:
            try:
                # Try to fetch code content
                if 'github.com' in poc.url:
                    code_content = self._fetch_github_code(poc.url, cve_id)
                    if code_content:
                        poc.code = code_content
                        poc.execution_command = self._generate_execution_command(poc.url, code_content)
                elif 'exploit-db.com' in poc.url:
                    code_content = self._fetch_exploitdb_code(poc.url)
                    if code_content:
                        poc.code = code_content
                        poc.execution_command = self._generate_execution_command(poc.url, code_content)
                
                enhanced_pocs.append(poc)
                
            except Exception as e:
                logger.debug(f"Failed to enhance PoC {poc.url}: {e}")
                enhanced_pocs.append(poc)  # Add without code if fetching fails
        
        return enhanced_pocs
    
    def _fetch_github_code(self, github_url: str, cve_id: str) -> str:
        """Fetch code content from GitHub repository"""
        try:
            # Extract repo info
            url_parts = github_url.replace('https://github.com/', '').split('/')
            if len(url_parts) >= 2:
                owner, repo = url_parts[0], url_parts[1]
                
                # Search for PoC files in the repository
                api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
                headers = {'Accept': 'application/vnd.github.v3+json'}
                
                response = requests.get(api_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    files = response.json()
                    
                    # Look for main PoC files
                    poc_file = self._find_main_poc_file(files, cve_id)
                    if poc_file:
                        # Fetch file content
                        file_response = requests.get(poc_file['download_url'], timeout=10)
                        if file_response.status_code == 200:
                            content = file_response.text
                            if len(content) < 10000:  # Limit code size for display
                                return content
                            else:
                                return content[:10000] + "\n\n... (truncated for display)"
                
        except Exception as e:
            logger.debug(f"Failed to fetch GitHub code from {github_url}: {e}")
        
        return ""
    
    def _find_main_poc_file(self, files: List[Dict], cve_id: str) -> Dict:
        """Find the main PoC file in a GitHub repository"""
        # Priority order for file matching
        priority_patterns = [
            cve_id.lower(),
            cve_id.replace('-', '_').lower(),
            'exploit',
            'poc',
            'main'
        ]
        
        # Preferred extensions
        preferred_extensions = ['.py', '.sh', '.rb', '.c', '.cpp']
        
        scored_files = []
        
        for file in files:
            if file.get('type') == 'file':
                filename = file.get('name', '').lower()
                score = 0
                
                # Score based on filename patterns
                for i, pattern in enumerate(priority_patterns):
                    if pattern in filename:
                        score += (len(priority_patterns) - i) * 10
                
                # Score based on file extension
                for ext in preferred_extensions:
                    if filename.endswith(ext):
                        score += 5
                        break
                
                # Penalties
                if any(avoid in filename for avoid in ['readme', 'license', 'test']):
                    score -= 20
                
                if score > 0:
                    scored_files.append((score, file))
        
        # Return highest scoring file
        if scored_files:
            scored_files.sort(key=lambda x: x[0], reverse=True)
            return scored_files[0][1]
        
        return None
    
    def _fetch_exploitdb_code(self, exploitdb_url: str) -> str:
        """Fetch code from ExploitDB"""
        try:
            # Convert web URL to raw URL
            exploit_id = re.search(r'/exploits/(\d+)', exploitdb_url)
            if exploit_id:
                raw_url = f"https://www.exploit-db.com/raw/{exploit_id.group(1)}"
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (compatible; BreachPilot)'
                }
                
                response = requests.get(raw_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    if len(content) < 10000:
                        return content
                    else:
                        return content[:10000] + "\n\n... (truncated for display)"
                
        except Exception as e:
            logger.debug(f"Failed to fetch ExploitDB code from {exploitdb_url}: {e}")
        
        return ""
    
    def _generate_execution_command(self, url: str, code: str) -> str:
        """Generate execution command based on URL and code content"""
        try:
            if 'github.com' in url:
                if code.startswith('#!/usr/bin/env python') or code.startswith('#!/usr/bin/python') or 'import ' in code[:200]:
                    return f"python3 exploit.py <target_ip>"
                elif code.startswith('#!/bin/bash') or code.startswith('#!/bin/sh') or 'bash' in code[:100]:
                    return f"bash exploit.sh <target_ip>"
                elif '#include' in code[:200] or 'int main' in code:
                    return f"gcc -o exploit exploit.c && ./exploit <target_ip>"
                else:
                    return f"./exploit <target_ip>"
            
            elif 'exploit-db.com' in url:
                if 'python' in code[:200].lower() or 'import ' in code[:200]:
                    return f"python3 exploit.py <target_ip>"
                elif 'bash' in code[:200].lower() or '#!/bin/' in code[:50]:
                    return f"bash exploit.sh <target_ip>"
                else:
                    return f"./exploit <target_ip>"
            
            return "See repository instructions"
            
        except Exception:
            return "Manual execution required"
    
    def _manual_rank_pocs(self, pocs: List[PoCInfo], cve_id: str) -> List[PoCInfo]:
        """Manual ranking as fallback"""
        def rank_score(poc: PoCInfo) -> tuple:
            score = 0
            
            # AI recommended bonus
            if getattr(poc, 'ai_recommended', False):
                score += 1000
                score += int(getattr(poc, 'ai_confidence', 0.5) * 100)
            
            # Source priority
            source_scores = {
                'AI Recommended GitHub': 900,
                'GitHub Repository': 800,
                'AI Recommended ExploitDB': 700,
                'ExploitDB': 600,
                'GitHub Code': 500
            }
            score += source_scores.get(poc.source, 0)
            
            # CVE in URL/description
            if cve_id.lower() in poc.url.lower():
                score += 200
            if cve_id.lower() in poc.description.lower():
                score += 100
            
            # Has code bonus
            if poc.code and poc.code.strip():
                score += 150
            
            # Stars
            score += min(poc.stars * 2, 50)
            
            return (score, poc.stars, len(poc.description))
        
        return sorted(pocs, key=rank_score, reverse=True)
    
    def _direct_search_enhanced(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Enhanced direct search as backup"""
        all_pocs = []
        
        # GitHub repositories
        github_repos = self._search_github_repositories_precise(cve_id, limit)
        all_pocs.extend(github_repos)
        
        # ExploitDB
        if len(all_pocs) < limit * 2:
            exploitdb_pocs = self._search_exploitdb(cve_id, limit)
            all_pocs.extend(exploitdb_pocs)
        
        # GitHub code files
        if len(all_pocs) < limit * 2:
            github_files = self._search_github_code_files_precise(cve_id, limit)
            all_pocs.extend(github_files)
        
        return all_pocs
    
    def _search_github_repositories_precise(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub repositories with precise CVE matching"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            search_queries = [
                f'"{cve_id}" in:name',
                f'"{cve_id}" PoC in:name,description',
                f'"{cve_id}" exploit in:name,description',
                f'"{cve_id}" proof concept'
            ]
            
            seen_repos = set()
            
            for query in search_queries:
                if len(pocs) >= limit * 2:
                    break
                
                try:
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
                            
                            repo_score = self._calculate_repo_score_strict(item, cve_id)
                            
                            if repo_score >= 50:
                                poc = PoCInfo(
                                    source='GitHub Repository',
                                    url=item['html_url'],
                                    description=self._clean_description(item.get('description', f'GitHub repository for {cve_id}')),
                                    author=item['owner']['login'],
                                    stars=item.get('stargazers_count', 0),
                                    code="",
                                    repo_score=repo_score
                                )
                                pocs.append(poc)
                                
                except Exception as e:
                    logger.debug(f"GitHub repo search query '{query}' failed: {e}")
                    continue
            
        except Exception as e:
            logger.warning(f"GitHub repository search failed: {e}")
        
        return pocs
    
    def _search_github_code_files_precise(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search GitHub code files"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
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
                            
                            repo_name = item['repository']['full_name'].lower()
                            if not any(bad in repo_name for bad in ['penetration-testing', 'toolkit', 'collection']):
                                poc = PoCInfo(
                                    source='GitHub Code',
                                    url=file_url,
                                    description=f'{cve_id} exploit: {item["name"]} in {item["repository"]["full_name"]}',
                                    author=item['repository']['owner']['login'],
                                    stars=item['repository'].get('stargazers_count', 0),
                                    code=""
                                )
                                pocs.append(poc)
                            
                except Exception as e:
                    logger.debug(f"GitHub code search failed: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"GitHub code search failed: {e}")
        
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
                exploit_ids = re.findall(r'/exploits/(\d+)', response.text)
                
                for exploit_id in exploit_ids[:limit]:
                    exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
                    
                    poc = PoCInfo(
                        source='ExploitDB',
                        url=exploit_url,
                        description=f'ExploitDB #{exploit_id} - {cve_id} exploit',
                        author='ExploitDB Community',
                        stars=0,
                        code=""
                    )
                    pocs.append(poc)
            
        except Exception as e:
            logger.debug(f"ExploitDB search error: {e}")
        
        return pocs
    
    def _calculate_repo_score_strict(self, repo_item: Dict, cve_id: str) -> int:
        """Calculate repository relevance score"""
        score = 0
        
        name = repo_item.get('name', '').lower()
        description = repo_item.get('description', '').lower()
        full_name = repo_item.get('full_name', '').lower()
        
        # Must have CVE ID mentioned
        cve_mentioned = (cve_id.lower() in name or 
                        cve_id.lower() in description or
                        cve_id.lower() in full_name)
        
        if not cve_mentioned:
            return -100
        
        # CVE in repository name
        if cve_id.lower() in name:
            score += 200
        
        # CVE in description
        if cve_id.lower() in description:
            score += 100
        
        # PoC/exploit keywords
        if any(keyword in name for keyword in ['poc', 'exploit', 'cve', 'vulnerability']):
            score += 50
        else:
            score -= 20
        
        # Stars bonus
        stars = repo_item.get('stargazers_count', 0)
        score += min(stars * 2, 30)
        
        # Recent activity
        updated_at = repo_item.get('updated_at', '')
        if '2024' in updated_at or '2023' in updated_at:
            score += 20
        elif '2022' in updated_at or '2021' in updated_at:
            score += 10
        else:
            score -= 10
        
        # Language bonus
        language = repo_item.get('language', '').lower()
        if language in ['python', 'shell', 'c', 'c++', 'go']:
            score += 15
        
        # Penalties for generic repos
        blacklist_patterns = [
            'awesome', 'list', 'collection', 'paper', 'research',
            'vulnerability-database', 'cve-database', 'security-tools',
            'penetration-testing', 'pentest', 'toolkit', 'framework',
            'scanner', 'fuzzer', 'multiple', 'various', 'general'
        ]
        
        for pattern in blacklist_patterns:
            if pattern in full_name or pattern in name or pattern in description:
                score -= 100
        
        return score
    
    def _clean_description(self, description: str) -> str:
        """Clean description"""
        if not description:
            return "PoC exploit repository"
        
        if len(re.findall(r'[\u4e00-\u9fff]', description)) > len(description) * 0.3:
            return "PoC exploit repository"
        
        if len(description) > 200:
            description = description[:200] + "..."
        
        return description
    
    def _deduplicate_and_filter_quality(self, pocs: List[PoCInfo], cve_id: str) -> List[PoCInfo]:
        """Remove duplicates and filter for quality"""
        unique_pocs = {}
        for poc in pocs:
            if poc.url not in unique_pocs:
                unique_pocs[poc.url] = poc
        
        quality_filtered = []
        for poc in unique_pocs.values():
            if self._is_quality_poc(poc, cve_id):
                quality_filtered.append(poc)
        
        return quality_filtered
    
    def _is_quality_poc(self, poc: PoCInfo, cve_id: str) -> bool:
        """Check PoC quality"""
        url_lower = poc.url.lower()
        desc_lower = poc.description.lower()
        
        if cve_id.lower() not in url_lower and cve_id.lower() not in desc_lower:
            return False
        
        blacklist = [
            'penetration-testing', 'pentest-tool', 'security-tool',
            'vulnerability-scanner', 'exploit-collection', 'awesome-',
            'hacking-tool', 'security-research', 'red-team'
        ]
        
        for term in blacklist:
            if term in url_lower or term in desc_lower:
                return False
        
        if 'various' in desc_lower or 'multiple' in desc_lower or 'collection' in desc_lower:
            return False
        
        return True
