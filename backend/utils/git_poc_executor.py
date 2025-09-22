import subprocess
import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class GitPoCExecutor:
    """Git-based PoC executor that clones repositories and executes directly"""
    
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="breachpilot_"))
        logger.info(f"Created temp directory: {self.temp_dir}")
    
    def execute_github_poc(self, github_url: str, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Clone GitHub repository and execute PoC"""
        try:
            # Extract repository info
            repo_name = self._extract_repo_name(github_url)
            if not repo_name:
                return {'success': False, 'output': 'Invalid GitHub URL', 'error': 'Invalid URL'}
            
            # Clone repository
            clone_path = self.temp_dir / repo_name.replace('/', '_')
            clone_result = self._clone_repository(github_url, clone_path)
            
            if not clone_result['success']:
                return clone_result
            
            # Find and execute PoC files
            execution_result = self._find_and_execute_poc(clone_path, target_ip, cve_id)
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Git PoC execution failed: {e}")
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e)}
    
    def _extract_repo_name(self, github_url: str) -> str:
        """Extract owner/repo from GitHub URL"""
        try:
            if 'github.com' in github_url:
                # Handle various GitHub URL formats
                if github_url.endswith('.git'):
                    github_url = github_url[:-4]
                
                parts = github_url.split('/')
                if len(parts) >= 2:
                    owner = parts[-2]
                    repo = parts[-1]
                    return f"{owner}/{repo}"
            
            return ""
        except Exception as e:
            logger.error(f"Error extracting repo name from {github_url}: {e}")
            return ""
    
    def _clone_repository(self, github_url: str, clone_path: Path) -> Dict[str, Any]:
        """Clone GitHub repository"""
        try:
            logger.info(f"Cloning repository: {github_url}")
            
            # Ensure clone path doesn't exist
            if clone_path.exists():
                shutil.rmtree(clone_path)
            
            # Git clone command
            cmd = ['git', 'clone', '--depth', '1', github_url, str(clone_path)]
            
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
            
            logger.info(f"Found {len(poc_files)} potential PoC files: {[str(f) for f in poc_files]}")
            
            # Try executing each PoC file until success
            execution_results = []
            
            for i, poc_file in enumerate(poc_files, 1):
                logger.info(f"Attempting to execute PoC #{i}: {poc_file.name}")
                
                result = self._execute_single_file(poc_file, target_ip, repo_path)
                execution_results.append(result)
                
                if result['success']:
                    logger.info(f"✓ PoC #{i} executed successfully!")
                    result['executed_file'] = str(poc_file)
                    result['all_attempts'] = execution_results
                    return result
                else:
                    logger.warning(f"✗ PoC #{i} failed: {result.get('error', 'Unknown error')}")
            
            # If no PoC succeeded, return the results from all attempts
            return {
                'success': False,
                'output': f'All {len(poc_files)} PoC files failed to execute successfully',
                'error': 'All PoCs failed',
                'all_attempts': execution_results,
                'files_tried': [str(f) for f in poc_files]
            }
            
        except Exception as e:
            return {'success': False, 'output': f'PoC search/execution error: {str(e)}', 'error': str(e)}
    
    def _search_poc_files(self, repo_path: Path, cve_id: str) -> List[Path]:
        """Search for PoC files in the repository"""
        poc_files = []
        
        try:
            # File extensions to look for
            extensions = ['.py', '.sh', '.rb', '.pl', '.c', '.cpp', '.go', '.java']
            
            # Search patterns (in order of priority)
            search_patterns = [
                cve_id.lower(),
                cve_id.replace('-', '_').lower(),
                cve_id.replace('CVE-', '').replace('cve-', ''),
                'exploit',
                'poc',
                'payload',
                'attack'
            ]
            
            # Search recursively in repository
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in extensions:
                    file_name = file_path.name.lower()
                    
                    # Calculate relevance score
                    score = 0
                    
                    # Higher score for CVE-specific files
                    for pattern in search_patterns:
                        if pattern in file_name:
                            score += (len(search_patterns) - search_patterns.index(pattern)) * 10
                    
                    # Bonus for executable extensions
                    if file_path.suffix.lower() in ['.py', '.sh']:
                        score += 5
                    
                    # Penalty for common non-PoC files
                    if any(exclude in file_name for exclude in ['readme', 'license', 'makefile', 'dockerfile']):
                        score -= 20
                    
                    # Only include files with positive scores
                    if score > 0:
                        poc_files.append((score, file_path))
            
            # Sort by score (highest first) and return file paths
            poc_files.sort(key=lambda x: x[0], reverse=True)
            sorted_files = [file_path for score, file_path in poc_files]
            
            # Limit to top 5 files to avoid excessive attempts
            return sorted_files[:5]
            
        except Exception as e:
            logger.error(f"Error searching PoC files: {e}")
            return []
    
    def _execute_single_file(self, file_path: Path, target_ip: str, repo_path: Path) -> Dict[str, Any]:
        """Execute a single PoC file"""
        try:
            extension = file_path.suffix.lower()
            
            # Make file executable if it's a script
            if extension in ['.sh', '.py', '.rb', '.pl']:
                os.chmod(file_path, 0o755)
            
            # Determine execution command based on file type
            if extension == '.py':
                cmd = ['python3', str(file_path), target_ip]
            elif extension == '.sh':
                cmd = ['bash', str(file_path), target_ip]
            elif extension == '.rb':
                cmd = ['ruby', str(file_path), target_ip]
            elif extension == '.pl':
                cmd = ['perl', str(file_path), target_ip]
            elif extension in ['.c', '.cpp']:
                # Try to compile and run C/C++ files
                return self._compile_and_execute_c(file_path, target_ip, repo_path)
            else:
                # Try to execute directly
                cmd = [str(file_path), target_ip]
            
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            # Execute with timeout and capture output
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,  # Execute in repository directory
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
        except FileNotFoundError as e:
            return {
                'success': False,
                'output': f'Required interpreter not found: {str(e)}',
                'error': str(e),
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': f'Execution error: {str(e)}',
                'error': str(e),
                'return_code': -1
            }
    
    def _compile_and_execute_c(self, file_path: Path, target_ip: str, repo_path: Path) -> Dict[str, Any]:
        """Compile and execute C/C++ files"""
        try:
            # Determine compiler
            compiler = 'gcc' if file_path.suffix == '.c' else 'g++'
            
            # Output binary name
            binary_path = file_path.with_suffix('')
            
            # Compile
            compile_cmd = [compiler, str(file_path), '-o', str(binary_path)]
            compile_result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30, cwd=repo_path)
            
            if compile_result.returncode != 0:
                return {
                    'success': False,
                    'output': f'Compilation failed: {compile_result.stderr}',
                    'error': 'Compilation failed',
                    'return_code': compile_result.returncode
                }
            
            # Execute the compiled binary
            os.chmod(binary_path, 0o755)
            exec_cmd = [str(binary_path), target_ip]
            
            exec_result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
                env=self._get_secure_env()
            )
            
            output = exec_result.stdout + exec_result.stderr
            success = self._analyze_execution_success(output, exec_result.returncode)
            
            return {
                'success': success,
                'output': output,
                'error': exec_result.stderr if not success else None,
                'return_code': exec_result.returncode,
                'command': ' '.join(exec_cmd),
                'compiled': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'output': f'C/C++ compilation/execution error: {str(e)}',
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
        
        # Strong success indicators
        success_indicators = [
            'exploit successful', 'successfully exploited', 'shell obtained',
            'access granted', 'vulnerability confirmed', 'target vulnerable',
            'privilege escalation', 'authentication bypassed'
        ]
        
        # Failure indicators
        failure_indicators = [
            'failed', 'error', 'exception', 'not vulnerable',
            'access denied', 'connection refused', 'timeout'
        ]
        
        # Check for explicit success messages
        if any(indicator in output_lower for indicator in success_indicators):
            return True
        
        # Check for explicit failure messages
        if any(indicator in output_lower for indicator in failure_indicators):
            return False
        
        # If return code is 0 and there's substantial output, consider success
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
