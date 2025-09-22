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
        self.exploits_dir = config.DATA_DIR / "exploits"
        self.exploits_dir.mkdir(exist_ok=True)
    
    def search_pocs(self, selected_cves: List[str], limit: int = 4) -> List[PoCResult]:
        """Search for PoC exploits for selected CVEs with enhanced collection"""
        logger.info(f"Searching PoCs for {len(selected_cves)} CVEs (limit: {limit} per CVE)")
        results = []
        
        for cve_id in selected_cves:
            pocs = self._search_single_cve_enhanced(cve_id, limit)
            
            # Save each PoC as separate file for easy execution
            saved_pocs = []
            for i, poc in enumerate(pocs, 1):
                if poc.code and poc.code.strip():
                    filename = self._save_poc_code(cve_id, poc, i)
                    if filename:
                        poc.filename = filename
                        poc.execution_command = self._generate_execution_command(filename, poc.code)
                        saved_pocs.append(poc)
                else:
                    # Try to fetch code if not already present
                    code = self._fetch_code_from_url(poc.url)
                    if code:
                        poc.code = code
                        filename = self._save_poc_code(cve_id, poc, i)
                        if filename:
                            poc.filename = filename
                            poc.execution_command = self._generate_execution_command(filename, code)
                            saved_pocs.append(poc)
                    else:
                        saved_pocs.append(poc)  # Keep it even without code for reference
            
            result = PoCResult(
                cve_id=cve_id,
                status=StepStatus.COMPLETED if saved_pocs else StepStatus.FAILED,
                available_pocs=saved_pocs
            )
            
            logger.info(f"Found {len(saved_pocs)} PoCs for {cve_id} ({len([p for p in saved_pocs if hasattr(p, 'filename')])} with code)")
            results.append(result)
        
        return results
    
    def _search_single_cve_enhanced(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Enhanced search for PoCs from multiple sources"""
        all_pocs = []
        
        # Search GitHub (multiple strategies)
        github_pocs = self._search_github_enhanced(cve_id, limit)
        all_pocs.extend(github_pocs)
        
        # Search ExploitDB
        exploitdb_pocs = self._search_exploitdb_enhanced(cve_id, limit)
        all_pocs.extend(exploitdb_pocs)
        
        # Search additional sources
        additional_pocs = self._search_additional_sources(cve_id, limit)
        all_pocs.extend(additional_pocs)
        
        # Deduplicate by URL and prioritize by quality
        unique_pocs = {}
        for poc in all_pocs:
            if poc.url not in unique_pocs:
                unique_pocs[poc.url] = poc
            elif len(poc.code) > len(unique_pocs[poc.url].code):
                unique_pocs[poc.url] = poc
        
        # Sort by quality (code length, stars, source priority)
        sorted_pocs = sorted(
            unique_pocs.values(),
            key=lambda p: (
                len(p.code) if p.code else 0,
                p.stars,
                1 if p.source == 'GitHub' else 2 if p.source == 'ExploitDB' else 3
            ),
            reverse=True
        )
        
        return sorted_pocs[:limit]
    
    def _search_github_enhanced(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Enhanced GitHub search with multiple strategies"""
        pocs = []
        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Enhanced search queries
            search_queries = [
                f'{cve_id} PoC',
                f'{cve_id} exploit',
                f'{cve_id} vulnerability python',
                f'"{cve_id}" proof of concept',
                f'{cve_id.replace("-", "_")} exploit'
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
                            
                            # Get exploit code from repo
                            code = self._fetch_exploit_code_from_repo(repo_name, cve_id)
                            
                            poc = PoCInfo(
                                source='GitHub',
                                url=item['html_url'],
                                description=item.get('description', ''),
                                author=item['owner']['login'],
                                stars=item.get('stargazers_count', 0),
                                code=code
                            )
                            pocs.append(poc)
                    
                    # Also search code directly
                    code_url = f'https://api.github.com/search/code?q={cve_id}+extension:py+OR+extension:sh'
                    code_response = requests.get(code_url, headers=headers, timeout=10)
                    
                    if code_response.status_code == 200:
                        code_data = code_response.json()
                        for item in code_data.get('items', [])[:3]:
                            if len(pocs) >= limit * 2:
                                break
                                
                            repo_name = item['repository']['full_name']
                            if repo_name in seen_repos:
                                continue
                                
                            file_path = item['path']
                            code = self._fetch_file_content(repo_name, file_path)
                            
                            if code and len(code.strip()) > 100:
                                poc = PoCInfo(
                                    source='GitHub Code',
                                    url=item['html_url'],
                                    description=f'Exploit code: {file_path}',
                                    author=item['repository']['owner']['login'],
                                    stars=item['repository'].get('stargazers_count', 0),
                                    code=code
                                )
                                pocs.append(poc)
                            
                except Exception as e:
                    logger.debug(f"GitHub search failed: {e}")
                    continue
            
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")
        
        return pocs
    
    def _fetch_exploit_code_from_repo(self, repo_name: str, cve_id: str) -> str:
        """Fetch exploit code from GitHub repo"""
        try:
            api_url = f'https://api.github.com/repos/{repo_name}/contents'
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                files = response.json()
                if not isinstance(files, list):
                    return ""
                
                # Look for exploit files with various patterns
                candidate_files = []
                
                for file_info in files:
                    if not isinstance(file_info, dict):
                        continue
                        
                    name = file_info.get('name', '').lower()
                    
                    # Score files based on relevance
                    score = 0
                    if cve_id.lower() in name:
                        score += 10
                    if any(ext in name for ext in ['.py', '.sh', '.rb', '.pl']):
                        score += 5
                    if any(keyword in name for keyword in ['exploit', 'poc', 'cve', 'vuln']):
                        score += 3
                    if 'readme' in name or 'license' in name:
                        score -= 5
                    
                    if score > 0:
                        candidate_files.append((score, file_info))
                
                # Sort by score and try to fetch content
                candidate_files.sort(key=lambda x: x[0], reverse=True)
                
                for score, file_info in candidate_files[:2]:
                    download_url = file_info.get('download_url')
                    if download_url:
                        try:
                            code_response = requests.get(download_url, timeout=10)
                            if code_response.status_code == 200:
                                content = code_response.text
                                if len(content.strip()) > 50:
                                    return content[:10000]
                        except:
                            continue
        
        except Exception as e:
            logger.debug(f"Error fetching from {repo_name}: {e}")
        
        return ""
    
    def _fetch_file_content(self, repo_name: str, file_path: str) -> str:
        """Fetch specific file content from GitHub repo"""
        try:
            api_url = f'https://api.github.com/repos/{repo_name}/contents/{file_path}'
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                file_data = response.json()
                if file_data.get('content'):
                    import base64
                    content = base64.b64decode(file_data['content']).decode('utf-8', errors='ignore')
                    return content[:10000]
        except Exception as e:
            logger.debug(f"Error fetching file content: {e}")
        
        return ""
    
    def _search_exploitdb_enhanced(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Enhanced ExploitDB search"""
        pocs = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            search_url = f'https://www.exploit-db.com/search?cve={cve_id}'
            response = requests.get(search_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse HTML for exploit IDs
                exploit_ids = re.findall(r'/exploits/(\d+)', response.text)
                
                # Remove duplicates while preserving order
                seen = set()
                unique_ids = []
                for eid in exploit_ids:
                    if eid not in seen:
                        seen.add(eid)
                        unique_ids.append(eid)
                
                for exploit_id in unique_ids[:limit]:
                    exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
                    raw_url = f'https://www.exploit-db.com/raw/{exploit_id}'
                    
                    # Fetch exploit code
                    code, description = self._fetch_exploitdb_details(exploit_id, raw_url)
                    
                    if code and len(code.strip()) > 50:
                        poc = PoCInfo(
                            source='ExploitDB',
                            url=exploit_url,
                            description=description or f'ExploitDB #{exploit_id}',
                            author='ExploitDB',
                            code=code
                        )
                        pocs.append(poc)
            
        except Exception as e:
            logger.warning(f"ExploitDB search failed: {e}")
        
        return pocs
    
    def _fetch_exploitdb_details(self, exploit_id: str, raw_url: str) -> tuple:
        """Fetch ExploitDB details"""
        code = ""
        description = ""
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/plain,text/html,*/*'
            }
            
            # Fetch raw exploit code
            code_response = requests.get(raw_url, headers=headers, timeout=15)
            if code_response.status_code == 200:
                code = code_response.text[:10000]
            
            # Fetch exploit page for description
            exploit_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
            page_response = requests.get(exploit_url, headers=headers, timeout=15)
            if page_response.status_code == 200:
                # Extract title/description from HTML
                title_patterns = [
                    r'<title>([^<]+)</title>',
                    r'<h1[^>]*>([^<]+)</h1>',
                    r'<h2[^>]*>([^<]+)</h2>'
                ]
                
                for pattern in title_patterns:
                    match = re.search(pattern, page_response.text, re.IGNORECASE)
                    if match:
                        description = match.group(1).strip()
                        if 'exploit-db' not in description.lower():
                            break
        
        except Exception as e:
            logger.debug(f"Error fetching ExploitDB details for {exploit_id}: {e}")
        
        return code, description
    
    def _search_additional_sources(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search additional sources for PoCs"""
        pocs = []
        
        # Search Packet Storm
        try:
            packetstorm_pocs = self._search_packetstorm(cve_id, limit)
            pocs.extend(packetstorm_pocs)
        except Exception as e:
            logger.debug(f"PacketStorm search failed: {e}")
        
        return pocs
    
    def _search_packetstorm(self, cve_id: str, limit: int) -> List[PoCInfo]:
        """Search Packet Storm"""
        pocs = []
        try:
            url = f'https://packetstormsecurity.com/search/?q={cve_id}'
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse for exploit links
                links = re.findall(r'href=\"(/files/[^\"]+)\"', response.text)
                
                for link in links[:limit]:
                    full_url = f'https://packetstormsecurity.com{link}'
                    
                    # Try to fetch code content
                    try:
                        code_response = requests.get(full_url, headers=headers, timeout=10)
                        if code_response.status_code == 200:
                            content = code_response.text
                            # Check if it's actual code/exploit content
                            if any(keyword in content.lower() for keyword in ['#!/', 'import', 'def ', 'class ', 'exploit']):
                                poc = PoCInfo(
                                    source='PacketStorm',
                                    url=full_url,
                                    description=f'PacketStorm Security - {link.split("/")[-1]}',
                                    author='PacketStorm',
                                    code=content[:10000] if len(content) < 50000 else content[:10000]
                                )
                                pocs.append(poc)
                    except:
                        # Add without code for reference
                        poc = PoCInfo(
                            source='PacketStorm',
                            url=full_url,
                            description=f'PacketStorm Security - {link.split("/")[-1]}',
                            author='PacketStorm'
                        )
                        pocs.append(poc)
        
        except Exception as e:
            logger.debug(f"PacketStorm search error: {e}")
        
        return pocs
    
    def _fetch_code_from_url(self, url: str) -> str:
        """Fetch code content from a URL"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                content = response.text
                
                # If it's a GitHub raw URL or similar, return directly
                if 'raw.githubusercontent.com' in url or any(ext in url for ext in ['.py', '.sh', '.rb', '.pl']):
                    return content[:10000]
                
                # If it's an HTML page, try to extract code blocks
                code_blocks = re.findall(r'<pre[^>]*>(.*?)</pre>', content, re.DOTALL)
                if code_blocks:
                    return code_blocks[0][:10000]
                
                # Look for code patterns in the content
                if any(keyword in content.lower() for keyword in ['#!/', 'import ', 'def ', 'class ', '#include']):
                    return content[:10000]
        
        except Exception as e:
            logger.debug(f"Error fetching code from {url}: {e}")
        
        return ""
    
    def _save_poc_code(self, cve_id: str, poc: PoCInfo, index: int) -> str:
        """Save PoC code to file with proper naming convention"""
        if not poc.code or not poc.code.strip():
            return ""
        
        try:
            # Generate filename: cve-xxxx-xxxx-001.py
            cve_clean = cve_id.replace('CVE-', '').replace('cve-', '')
            extension = self._detect_file_extension(poc.code)
            filename = f"cve-{cve_clean}-{index:03d}.{extension}"
            filepath = self.exploits_dir / filename
            
            # Add execution metadata as comments
            metadata = f"""#!/usr/bin/env python3
# CVE: {cve_id}
# Source: {poc.source}
# Author: {poc.author}
# URL: {poc.url}
# Description: {poc.description}
# Generated by BreachPilot

"""
            
            # Write code with metadata
            with open(filepath, 'w', encoding='utf-8') as f:
                if extension == 'py':
                    f.write(metadata)
                f.write(poc.code)
            
            # Make executable
            os.chmod(filepath, 0o755)
            
            return filename
            
        except Exception as e:
            logger.error(f"Error saving PoC code: {e}")
            return ""
    
    def _detect_file_extension(self, code: str) -> str:
        """Detect appropriate file extension based on code content"""
        code_lower = code.lower()
        
        if any(keyword in code_lower for keyword in ['import ', 'def ', 'class ', 'from ', 'print(']):
            return 'py'
        elif any(keyword in code_lower for keyword in ['#!/bin/bash', '#!/bin/sh', 'curl ', 'wget ']):
            return 'sh'
        elif any(keyword in code_lower for keyword in ['require ', 'def ', 'class ', 'puts ']):
            return 'rb'
        elif any(keyword in code_lower for keyword in ['use ', 'sub ', 'my ', '$']):
            return 'pl'
        else:
            # Default to Python for most exploits
            return 'py'
    
    def _generate_execution_command(self, filename: str, code: str) -> str:
        """Generate appropriate execution command for the PoC"""
        extension = filename.split('.')[-1]
        
        if extension == 'py':
            return f"python3 {filename} [TARGET_IP]"
        elif extension == 'sh':
            return f"bash {filename} [TARGET_IP]"
        elif extension == 'rb':
            return f"ruby {filename} [TARGET_IP]"
        elif extension == 'pl':
            return f"perl {filename} [TARGET_IP]"
        else:
            return f"./{filename} [TARGET_IP]"
