import subprocess
import os
import tempfile
import shutil
import requests
from pathlib import Path
from typing import Dict, Any, List
import logging
import re
import json

logger = logging.getLogger(__name__)

class GitPoCExecutor:
    """Basic Git-based PoC executor that clones repositories and executes intelligently"""
    
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="breachpilot_"))
        logger.info(f"Created temp directory: {self.temp_dir}")
    
    def execute_github_poc(self, github_url: str, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Clone GitHub repository and execute PoC intelligently"""
        try:
            # Extract repository info
            repo_info = self._extract_repo_info(github_url)
            if not repo_info:
                return {'success': False, 'output': 'Invalid GitHub URL', 'error': 'Invalid URL'}
            
            # Clone repository
            clone_path = self.temp_dir / repo_info['repo_name'].replace('/', '_')
            clone_result = self._clone_repository(repo_info['clone_url'], clone_path)
            
            if not clone_result['success']:
                return clone_result
            
            # Find and execute PoC files
            execution_result = self._find_and_execute_poc(clone_path, target_ip, cve_id)
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Git PoC execution failed: {e}")
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e)}
    
    def _extract_repo_info(self, github_url: str) -> Dict[str, str]:
        """Extract repository information from GitHub URL"""
        try:
            url = github_url.replace('https://github.com/', '').replace('http://github.com/', '')
            if url.endswith('.git'):
                url = url[:-4]
            
            parts = url.split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
                return {
                    'owner': owner,
                    'repo': repo,
                    'repo_name': f"{owner}/{repo}",
                    'clone_url': f"https://github.com/{owner}/{repo}.git",
                    'api_url': f"https://api.github.com/repos/{owner}/{repo}"
                }
            return None
        except Exception as e:
            logger.error(f"Error extracting repo info from {github_url}: {e}")
            return None
    
    def _clone_repository(self, clone_url: str, clone_path: Path) -> Dict[str, Any]:
        """Clone GitHub repository"""
        try:
            logger.info(f"Cloning repository: {clone_url}")
            
            if clone_path.exists():
                shutil.rmtree(clone_path)
            
            cmd = ['git', 'clone', '--depth', '1', clone_url, str(clone_path)]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.temp_dir
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully cloned to {clone_path}")
                return {'success': True, 'output': result.stdout, 'path': clone_path}
            else:
                logger.error(f"Git clone failed: {result.stderr}")
                return {'success': False, 'output': result.stderr, 'error': 'Clone failed'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Git clone timed out', 'error': 'Timeout'}
        except FileNotFoundError:
            return {'success': False, 'output': 'Git not found. Please install git.', 'error': 'Git not available'}
        except Exception as e:
            return {'success': False, 'output': f'Clone error: {str(e)}', 'error': str(e)}
    
    def _find_and_execute_poc(self, repo_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Find PoC files in repository and execute them"""
        try:
            logger.info(f"Searching for PoC files in {repo_path}")
            
            # Search for potential PoC files
            poc_files = self._search_poc_files(repo_path, cve_id)
            
            if not poc_files:
                return {'success': False, 'output': f'No PoC files found in repository', 'error': 'No PoC files'}
            
            logger.info(f"Found {len(poc_files)} potential PoC files")
            
            # Try executing each PoC file until success
            for i, poc_file in enumerate(poc_files, 1):
                logger.info(f"Attempting to execute PoC #{i}: {poc_file.name}")
                
                result = self._execute_single_file(poc_file, target_ip, repo_path)
                
                if result['success']:
                    logger.info(f"✓ PoC #{i} executed successfully!")
                    result['executed_file'] = str(poc_file)
                    return result
                else:
                    logger.warning(f"✗ PoC #{i} failed: {result.get('error', 'Unknown error')}")
            
            return {
                'success': False,
                'output': f'All {len(poc_files)} PoC files failed to execute successfully',
                'error': 'All PoCs failed',
                'files_tried': [str(f) for f in poc_files]
            }
            
        except Exception as e:
            return {'success': False, 'output': f'PoC search/execution error: {str(e)}', 'error': str(e)}
    
    def _search_poc_files(self, repo_path: Path, cve_id: str) -> List[Path]:
        """Search for PoC files in the repository"""
        poc_files = []
        
        try:
            extensions = ['.py', '.sh', '.rb', '.pl', '.c', '.cpp']
            
            search_patterns = [
                cve_id.lower(),
                cve_id.replace('-', '_').lower(),
                cve_id.replace('CVE-', '').replace('cve-', ''),
                'exploit',
                'poc'
            ]
            
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in extensions:
                    file_name = file_path.name.lower()
                    
                    score = 0
                    for pattern in search_patterns:
                        if pattern in file_name:
                            score += (len(search_patterns) - search_patterns.index(pattern)) * 10
                    
                    if file_path.suffix.lower() in ['.py', '.sh']:
                        score += 5
                    
                    if any(exclude in file_name for exclude in ['readme', 'license', 'test']):
                        score -= 20
                    
                    if score > 0:
                        poc_files.append((score, file_path))
            
            poc_files.sort(key=lambda x: x[0], reverse=True)
            return [file_path for score, file_path in poc_files[:5]]
            
        except Exception as e:
            logger.error(f"Error searching PoC files: {e}")
            return []
    
    def _execute_single_file(self, file_path: Path, target_ip: str, repo_path: Path) -> Dict[str, Any]:
        """Execute a single PoC file"""
        try:
            extension = file_path.suffix.lower()
            
            if extension in ['.sh', '.py', '.rb', '.pl']:
                os.chmod(file_path, 0o755)
            
            if extension == '.py':
                cmd = ['python3', str(file_path), target_ip]
            elif extension == '.sh':
                cmd = ['bash', str(file_path), target_ip]
            elif extension == '.rb':
                cmd = ['ruby', str(file_path), target_ip]
            elif extension == '.pl':
                cmd = ['perl', str(file_path), target_ip]
            else:
                cmd = [str(file_path), target_ip]
            
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
                env=self._get_secure_env()
            )
            
            output = result.stdout + result.stderr
            success = self._analyze_execution_success(output, result.returncode)
            
            return {
                'success': success,
                'output': output,
                'error': result.stderr if not success else None,
                'return_code': result.returncode,
                'command': ' '.join(cmd),
                'file_executed': str(file_path)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': f'Execution of {file_path.name} timed out after 120 seconds',
                'error': 'Timeout',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': f'Execution error: {str(e)}',
                'error': str(e),
                'return_code': -1
            }
    
    def _get_secure_env(self) -> Dict[str, str]:
        """Get secure environment variables"""
        return {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': '/tmp',
            'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8'
        }
    
    def _analyze_execution_success(self, output: str, return_code: int) -> bool:
        """Analyze if execution was successful"""
        output_lower = output.lower()
        
        success_indicators = [
            'exploit successful', 'successfully exploited', 'shell obtained',
            'access granted', 'vulnerability confirmed', 'target vulnerable',
            'privilege escalation', 'authentication bypassed'
        ]
        
        failure_indicators = [
            'failed', 'error', 'exception', 'not vulnerable',
            'access denied', 'connection refused', 'timeout'
        ]
        
        if any(indicator in output_lower for indicator in success_indicators):
            return True
        
        if any(indicator in output_lower for indicator in failure_indicators):
            return False
        
        if return_code == 0 and len(output.strip()) > 20:
            return True
        
        return False
    
    def cleanup(self):
        """Clean up temporary directories"""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temp directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup temp directory: {e}")
    
    def __del__(self):
        """Ensure cleanup on object destruction"""
        self.cleanup()
