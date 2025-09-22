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
            # Create specialized AI agents
            poc_hunter = Agent(
                role='PoC Hunter Agent',
                goal=f'Find the best proof-of-concept exploits for {cve_id}',
                backstory="""You are an elite cybersecurity researcher specializing in exploit hunting.
                Your expertise lies in finding high-quality, working proof-of-concept exploits from
                GitHub, ExploitDB, and other security repositories. You prioritize:
                1. GitHub repositories with specific CVE names
                2. Recent, actively maintained repositories
                3. Repositories with clear documentation
                4. Code that appears to be functional and well-written""",
                llm=self.llm,
                verbose=True
            )
            
            quality_analyzer = Agent(
                role='PoC Quality Analyst',
                goal=f'Analyze and rank PoC exploits for {cve_id} by quality and reliability',
                backstory="""You are a senior penetration tester with expertise in evaluating
                exploit quality. You can assess PoC exploits based on:
                1. Code quality and completeness
                2. Repository maintenance and community trust
                3. Compatibility and likelihood of success
                4. Documentation and usage clarity""",
                llm=self.llm,
                verbose=False
            )
            
            # Create tasks
            hunt_task = Task(
                description=f"""Find the best PoC exploits for {cve_id}.
                
                Search Strategy:
                1. Look for GitHub repositories with exact CVE ID in name or description
                2. Search for recent, well-maintained repositories
                3. Find ExploitDB entries for this CVE
                4. Look for specific exploit files (.py, .sh, .c, etc.)
                
                Focus on quality over quantity. Find {limit} high-quality PoCs that:
                - Are specifically for {cve_id} (not generic collections)
                - Have clear, working code
                - Are from reputable sources
                - Have good documentation or comments
                
                Return a structured list of the best PoCs found.""",
                agent=poc_hunter,
                expected_output=f"A detailed list of {limit} high-quality PoC exploits for {cve_id}"
            )
            
            analyze_task = Task(
                description=f"""Analyze the PoC exploits found for {cve_id} and rank them by quality.
                
                Evaluation Criteria:
                1. Code Quality: Is the code well-written and complete?
                2. Specificity: Is it specifically for {cve_id}?
                3. Recency: How recent is the repository/code?
                4. Community Trust: Stars, forks, contributor reputation
                5. Documentation: Clear instructions and comments
                6. Functionality: Does it look like it would work?
                
                Rank the PoCs from best to worst and explain why each one is valuable.""",
                agent=quality_analyzer,
                expected_output=f"Ranked analysis of PoC exploits for {cve_id} with quality scores"
            )
            
            # Execute AI crew
            crew = Crew(
                agents=[poc_hunter, quality_analyzer],
                tasks=[hunt_task, analyze_task],
                process=Process.sequential,
                verbose=True
            )
            
            logger.info(f"🤖 AI Crew starting analysis for {cve_id}...")
            crew_result = crew.kickoff()
            
            # Parse AI results and combine with direct search
            ai_recommendations = self._parse_ai_recommendations(str(crew_result), cve_id)
            direct_results = self._direct_search_enhanced(cve_id, limit)
            
            # Combine and deduplicate
            all_pocs = ai_recommendations + direct_results
            unique_pocs = self._deduplicate_and_filter_quality(all_pocs, cve_id)
            
            # Final AI-assisted ranking
            final_pocs = self._ai_rank_final_pocs(unique_pocs, cve_id, limit)
            
            search_duration = round(time.time() - start_time, 2)
            logger.info(f"🎯 AI-enhanced search completed in {search_duration}s")
            
            return final_pocs
            
        except Exception as e:
            logger.error(f"AI-enhanced PoC search failed for {cve_id}: {e}")
            # Fallback to direct search
            return self._direct_search_enhanced(cve_id, limit)
    
    def _parse_ai_recommendations(self, ai_result: str, cve_id: str) -> List[PoCInfo]:
        """Parse AI agent recommendations into PoC objects"""
        pocs = []
        
        # Extract GitHub URLs from AI response
        github_urls = re.findall(r'https://github\.com/[\w\-\.]+/[\w\-\.]+', ai_result)
        
        # Extract ExploitDB URLs
        exploitdb_urls = re.findall(r'https://www\.exploit-db\.com/exploits/\d+', ai_result)
        
        # Process GitHub URLs
        for url in github_urls:
            if len(pocs) >= 10:  # Limit AI recommendations
                break
            try:
                # Get repository info
                repo_info = self._get_github_repo_info(url)
                if repo_info and self._validate_ai_recommendation(repo_info, cve_id, ai_result):
                    poc = PoCInfo(
                        source='AI Recommended GitHub',
                        url=url,
                        description=repo_info.get('description', f'AI-recommended PoC for {cve_id}'),
                        author=repo_info.get('owner', {}).get('login', 'Unknown'),
                        stars=repo_info.get('stargazers_count', 0),
                        code="",
                        ai_recommended=True,
                        ai_confidence=self._extract_ai_confidence(url, ai_result)
                    )
                    pocs.append(poc)
            except Exception as e:
                logger.debug(f"Failed to process AI recommendation {url}: {e}")
        
        # Process ExploitDB URLs
        for url in exploitdb_urls:
            if len(pocs) >= 10:
                break
            poc = PoCInfo(
                source='AI Recommended ExploitDB',
                url=url,
                description=f'AI-recommended ExploitDB exploit for {cve_id}',
                author='ExploitDB Community',
                stars=0,
                code="",
                ai_recommended=True,
                ai_confidence=self._extract_ai_confidence(url, ai_result)
            )
            pocs.append(poc)
        
        logger.info(f"🤖 AI Agent extracted {len(pocs)} recommendations from analysis")
        return pocs
    
    def _validate_ai_recommendation(self, repo_info: Dict, cve_id: str, ai_result: str) -> bool:
        """Validate if AI recommendation is actually good"""
        repo_name = repo_info.get('name', '').lower()
        description = repo_info.get('description', '').lower()
        
        # Must mention CVE
        if cve_id.lower() not in repo_name and cve_id.lower() not in description:
            return False
        
        # Check if AI mentioned why it's good
        repo_url = repo_info.get('html_url', '')
        if repo_url in ai_result:
            # Look for positive AI keywords around this URL
            url_context = ai_result[max(0, ai_result.find(repo_url) - 200):ai_result.find(repo_url) + 200]
            positive_indicators = ['high quality', 'well maintained', 'good documentation', 'working', 'reliable', 'recommended']
            if any(indicator in url_context.lower() for indicator in positive_indicators):
                return True
        
        return False
    
    def _extract_ai_confidence(self, url: str, ai_result: str) -> float:
        """Extract AI confidence score from analysis text"""
        if url in ai_result:
            # Look for confidence indicators
            url_context = ai_result[max(0, ai_result.find(url) - 100):ai_result.find(url) + 100].lower()
            
            if 'excellent' in url_context or 'best' in url_context:
                return 0.95
            elif 'good' in url_context or 'quality' in url_context:
                return 0.85
            elif 'recommended' in url_context:
                return 0.75
            else:
                return 0.65
        
        return 0.6
    
    def _get_github_repo_info(self, url: str) -> Dict:
        """Get GitHub repository information"""
        try:
            # Extract owner/repo from URL
            parts = url.replace('https://github.com/', '').split('/')
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                api_url = f'https://api.github.com/repos/{owner}/{repo}'
                
                headers = {'Accept': 'application/vnd.github.v3+json'}
                response = requests.get(api_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            logger.debug(f"Failed to get repo info for {url}: {e}")
        
        return None
    
    def _ai_rank_final_pocs(self, pocs: List[PoCInfo], cve_id: str, limit: int) -> List[PoCInfo]:
        """Use AI to do final ranking of PoCs"""
        if len(pocs) <= limit:
            return pocs
        
        try:
            # Create ranking agent
            ranker = Agent(
                role='PoC Ranking Specialist',
                goal=f'Rank PoC exploits for {cve_id} in order of likely success',
                backstory="""You are an expert at evaluating cybersecurity exploits and determining
                which ones are most likely to work in real penetration testing scenarios.""",
                llm=self.llm,
                verbose=False
            )
            
            # Prepare PoC summaries for AI
            poc_summaries = []
            for i, poc in enumerate(pocs):
                summary = f"""PoC #{i+1}:
                Source: {poc.source}
                URL: {poc.url}
                Description: {poc.description}
                Author: {poc.author}
                Stars: {poc.stars}
                AI Recommended: {getattr(poc, 'ai_recommended', False)}"""
                poc_summaries.append(summary)
            
            rank_task = Task(
                description=f"""Rank these {len(pocs)} PoC exploits for {cve_id} in order of likely success.
                Consider: code quality, source reliability, community trust, and specificity to {cve_id}.
                
                PoCs to rank:
                {chr(10).join(poc_summaries)}
                
                Return just the numbers (e.g., "3,1,5,2,4") for the ranking from best to worst.""",
                agent=ranker,
                expected_output="Comma-separated ranking numbers"
            )
            
            crew = Crew(agents=[ranker], tasks=[rank_task], process=Process.sequential, verbose=False)
            result = crew.kickoff()
            
            # Parse ranking
            ranking_str = str(result).strip()
            ranking_match = re.search(r'[\d,\s]+', ranking_str)
            
            if ranking_match:
                ranking_numbers = [int(x.strip()) for x in ranking_match.group().split(',') if x.strip().isdigit()]
                
                # Apply ranking
                ranked_pocs = []
                for rank_num in ranking_numbers:
                    if 1 <= rank_num <= len(pocs):
                        ranked_pocs.append(pocs[rank_num - 1])
                
                # Add any missing PoCs
                for poc in pocs:
                    if poc not in ranked_pocs:
                        ranked_pocs.append(poc)
                
                logger.info(f"🤖 AI Agent ranked {len(ranked_pocs)} PoCs for {cve_id}")
                return ranked_pocs[:limit]
        
        except Exception as e:
            logger.debug(f"AI ranking failed: {e}")
        
        # Fallback to manual ranking
        return self._manual_rank_pocs(pocs, cve_id)[:limit]
    
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
                exploit_ids = re.findall(r'/exploits/(\\d+)', response.text)
                
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
        
        if len(re.findall(r'[\\u4e00-\\u9fff]', description)) > len(description) * 0.3:
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
