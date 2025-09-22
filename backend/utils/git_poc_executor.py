import subprocess
import os
import tempfile
import shutil
import requests
from pathlib import Path
from typing import Dict, Any, List
import logging
import re

logger = logging.getLogger(__name__)

class GitPoCExecutor:
    """Git-based PoC executor that clones repositories and executes directly"""
    
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
            
            # Read README for execution instructions
            readme_instructions = self._analyze_readme(clone_path, cve_id)
            
            # Find and execute PoC files
            execution_result = self._find_and_execute_poc(clone_path, target_ip, cve_id, readme_instructions)
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Git PoC execution failed: {e}")
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e)}
    
    def _extract_repo_info(self, github_url: str) -> Dict[str, str]:
        """Extract repository information from GitHub URL"""
        try:
            # Clean up URL
            url = github_url.replace('https://github.com/', '').replace('http://github.com/', '')
            if url.endswith('.git'):
                url = url[:-4]
            
            # Extract owner/repo
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
            
            # Ensure clone path doesn't exist
            if clone_path.exists():
                shutil.rmtree(clone_path)
            
            # Git clone command
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
    
    def _analyze_readme(self, repo_path: Path, cve_id: str) -> Dict[str, Any]:
        """Analyze README.md for execution instructions"""
        instructions = {
            'execution_commands': [],
            'main_files': [],
            'dependencies': [],
            'usage_examples': []
        }
        
        try:
            # Look for README files
            readme_files = []
            for pattern in ['README.md', 'readme.md', 'README.txt', 'README.rst', 'README']:
                readme_path = repo_path / pattern
                if readme_path.exists():
                    readme_files.append(readme_path)
            
            for readme_path in readme_files:
                logger.info(f"Analyzing README: {readme_path}")
                
                with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract execution commands
                self._extract_commands_from_readme(content, instructions, cve_id)
                
                # Extract main files mentioned
                self._extract_main_files_from_readme(content, instructions, cve_id)
                
                # Extract dependencies
                self._extract_dependencies_from_readme(content, instructions)
                
                break  # Use first README found
            
        except Exception as e:
            logger.warning(f"Error analyzing README: {e}")
        
        return instructions
    
    def _extract_commands_from_readme(self, content: str, instructions: Dict, cve_id: str):
        """Extract execution commands from README content"""
        # Look for code blocks with python/bash commands
        code_blocks = re.findall(r'```(?:python|bash|sh)?\n(.*?)```', content, re.DOTALL)
        
        for block in code_blocks:
            lines = block.strip().split('\n')
            for line in lines:
                line = line.strip()
                
                # Look for python execution
                if line.startswith('python') and any(keyword in line.lower() for keyword in [cve_id.lower(), 'exploit', 'poc', '.py']):
                    instructions['execution_commands'].append({
                        'command': line,
                        'type': 'python',
                        'priority': 10
                    })
                
                # Look for direct script execution
                elif line.startswith('./') and any(ext in line for ext in ['.py', '.sh']):
                    instructions['execution_commands'].append({
                        'command': line,
                        'type': 'direct',
                        'priority': 8
                    })
        
        # Look for inline command examples
        inline_commands = re.findall(r'`([^`]*(?:python|\.py|exploit)[^`]*)`', content, re.IGNORECASE)
        for cmd in inline_commands:
            if any(keyword in cmd.lower() for keyword in [cve_id.lower(), 'exploit', 'poc']):
                instructions['execution_commands'].append({
                    'command': cmd.strip(),
                    'type': 'inline',
                    'priority': 6
                })
    
    def _extract_main_files_from_readme(self, content: str, instructions: Dict, cve_id: str):
        """Extract main executable files mentioned in README"""
        # Look for file mentions
        file_patterns = [
            rf'({cve_id.lower()}[.\w]*\.py)',
            rf'(exploit[.\w]*\.py)',
            rf'(poc[.\w]*\.py)',
            rf'([.\w]*{cve_id.lower()}[.\w]*)',
            rf'([.\w]*exploit[.\w]*\.py)',
            rf'([.\w]*poc[.\w]*\.py)'
        ]
        
        for pattern in file_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and match.endswith(('.py', '.sh', '.rb', '.pl')):
                    instructions['main_files'].append(match)
    
    def _extract_dependencies_from_readme(self, content: str, instructions: Dict):
        """Extract dependencies from README"""
        # Look for pip install commands
        pip_installs = re.findall(r'pip install ([^\n]+)', content)
        instructions['dependencies'].extend(pip_installs)
        
        # Look for requirements.txt mention
        if 'requirements.txt' in content:
            instructions['dependencies'].append('requirements.txt')
    
    def _find_and_execute_poc(self, repo_path: Path, target_ip: str, cve_id: str, readme_instructions: Dict) -> Dict[str, Any]:
        """Find PoC files in repository and execute them intelligently"""
        try:
            logger.info(f"Searching for PoC files in {repo_path}")
            
            # Install dependencies if needed
            self._install_dependencies(repo_path, readme_instructions)
            
            # Get execution plan based on README + file analysis
            execution_plan = self._create_execution_plan(repo_path, cve_id, readme_instructions)
            
            if not execution_plan:
                return {'success': False, 'output': 'No executable PoC files found in repository', 'error': 'No PoC files'}
            
            logger.info(f"Found {len(execution_plan)} execution targets")
            
            # Try executing each target until success
            execution_results = []
            
            for i, target in enumerate(execution_plan, 1):
                logger.info(f"Attempting execution #{i}: {target['description']}")
                
                result = self._execute_target(target, target_ip, repo_path)
                execution_results.append(result)
                
                if result['success']:
                    logger.info(f"✓ Execution #{i} succeeded!")
                    result['executed_target'] = target
                    result['all_attempts'] = execution_results
                    return result
                else:
                    logger.warning(f"✗ Execution #{i} failed: {result.get('error', 'Unknown error')}")
            
            # If no execution succeeded
            return {
                'success': False,
                'output': f'All {len(execution_plan)} execution attempts failed',
                'error': 'All executions failed',
                'all_attempts': execution_results,
                'targets_tried': [t['description'] for t in execution_plan]
            }
            
        except Exception as e:
            return {'success': False, 'output': f'PoC execution error: {str(e)}', 'error': str(e)}
    
    def _install_dependencies(self, repo_path: Path, readme_instructions: Dict):
        """Install dependencies if specified"""
        try:
            # Install from requirements.txt if exists
            requirements_file = repo_path / 'requirements.txt'
            if requirements_file.exists():
                logger.info("Installing dependencies from requirements.txt")
                subprocess.run(['pip', 'install', '-r', str(requirements_file)], 
                             capture_output=True, timeout=120)
            
            # Install individual dependencies
            for dep in readme_instructions.get('dependencies', []):
                if dep != 'requirements.txt':
                    logger.info(f"Installing dependency: {dep}")
                    subprocess.run(['pip', 'install', dep], 
                                 capture_output=True, timeout=60)
                    
        except Exception as e:
            logger.warning(f"Failed to install dependencies: {e}")
    
    def _create_execution_plan(self, repo_path: Path, cve_id: str, readme_instructions: Dict) -> List[Dict]:
        """Create intelligent execution plan based on README and files"""
        execution_plan = []
        
        # Priority 1: Commands from README
        for cmd_info in readme_instructions.get('execution_commands', []):
            command = cmd_info['command']
            
            # Parse command to extract file and arguments
            if command.startswith('python'):
                parts = command.split()
                if len(parts) > 1:
                    file_path = repo_path / parts[1]
                    if file_path.exists():
                        execution_plan.append({
                            'type': 'readme_command',
                            'file_path': file_path,
                            'command_template': command,
                            'description': f"README command: {command}",
                            'priority': cmd_info['priority']
                        })
        
        # Priority 2: Main files mentioned in README
        for filename in readme_instructions.get('main_files', []):
            file_path = repo_path / filename
            if file_path.exists():
                execution_plan.append({
                    'type': 'readme_file',
                    'file_path': file_path,
                    'description': f"README mentioned file: {filename}",
                    'priority': 8
                })
        
        # Priority 3: Auto-discovered files
        discovered_files = self._discover_poc_files(repo_path, cve_id)
        for file_info in discovered_files:
            execution_plan.append({
                'type': 'discovered',
                'file_path': file_info['path'],
                'description': f"Discovered file: {file_info['name']} (score: {file_info['score']})",
                'priority': file_info['score'] // 10
            })
        
        # Sort by priority (highest first)
        execution_plan.sort(key=lambda x: x['priority'], reverse=True)
        
        # Remove duplicates
        seen_files = set()
        unique_plan = []
        for target in execution_plan:
            file_str = str(target['file_path'])
            if file_str not in seen_files:
                seen_files.add(file_str)
                unique_plan.append(target)
        
        return unique_plan[:5]  # Limit to top 5 targets
    
    def _discover_poc_files(self, repo_path: Path, cve_id: str) -> List[Dict]:
        """Discover PoC files automatically"""
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
                'attack',
                'payload'
            ]
            
            # Search recursively in repository
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in extensions:
                    file_name = file_path.name.lower()
                    
                    # Calculate relevance score
                    score = 0
                    
                    # Higher score for CVE-specific files
                    for i, pattern in enumerate(search_patterns):
                        if pattern in file_name:
                            score += (len(search_patterns) - i) * 15
                    
                    # Bonus for executable extensions
                    if file_path.suffix.lower() in ['.py', '.sh']:
                        score += 10
                    
                    # Bonus for main/root directory files
                    if file_path.parent == repo_path:
                        score += 20
                    
                    # Penalty for common non-PoC files
                    if any(exclude in file_name for exclude in ['readme', 'license', 'makefile', 'dockerfile', 'requirements']):
                        score -= 30
                    
                    # Only include files with positive scores
                    if score > 0:
                        poc_files.append({
                            'path': file_path,
                            'name': file_path.name,
                            'score': score
                        })
            
            # Sort by score (highest first)
            poc_files.sort(key=lambda x: x['score'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error discovering PoC files: {e}")
        
        return poc_files
    
    def _execute_target(self, target: Dict, target_ip: str, repo_path: Path) -> Dict[str, Any]:
        """Execute a specific target"""
        try:
            file_path = target['file_path']
            extension = file_path.suffix.lower()
            
            # Make file executable if it's a script
            if extension in ['.sh', '.py', '.rb', '.pl']:
                os.chmod(file_path, 0o755)
            
            # Determine execution command
            if target['type'] == 'readme_command' and 'command_template' in target:
                # Use command from README, substitute target IP
                cmd_template = target['command_template']
                cmd_parts = cmd_template.split()
                
                # Add target IP as argument if not present
                if target_ip not in cmd_template:
                    cmd_parts.append(target_ip)
                
                cmd = cmd_parts
            else:
                # Standard execution based on file type
                if extension == '.py':
                    cmd = ['python3', str(file_path), target_ip]
                elif extension == '.sh':
                    cmd = ['bash', str(file_path), target_ip]
                elif extension == '.rb':
                    cmd = ['ruby', str(file_path), target_ip]
                elif extension == '.pl':
                    cmd = ['perl', str(file_path), target_ip]
                elif extension in ['.c', '.cpp']:
                    return self._compile_and_execute_c(file_path, target_ip, repo_path)
                else:
                    cmd = [str(file_path), target_ip]
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
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
            'privilege escalation', 'authentication bypassed', 'exploit completed'
        ]
        
        # Failure indicators
        failure_indicators = [
            'failed', 'error', 'exception', 'not vulnerable',
            'access denied', 'connection refused', 'timeout',
            'syntaxerror', 'traceback'
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
