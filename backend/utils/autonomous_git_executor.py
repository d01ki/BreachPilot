    def _analyze_failure(self, result: Dict) -> str:
        """Analyze failure type for adaptive learning"""
        output = result.get('output', '').lower()
        error = result.get('error', '').lower()
        full_text = output + ' ' + error
        
        if 'syntax' in full_text:
            return 'syntax_error'
        elif 'not found' in full_text or 'no such file' in full_text:
            return 'file_not_found'
        elif 'permission' in full_text or 'access denied' in full_text:
            return 'permission_error'
        elif 'import' in full_text and 'error' in full_text:
            return 'missing_dependency'
        elif 'usage' in full_text or 'argument' in full_text:
            return 'argument_error'
        elif 'timeout' in full_text:
            return 'timeout_error'
        elif 'connection' in full_text and ('refused' in full_text or 'failed' in full_text):
            return 'connection_error'
        elif result.get('return_code') == 0 and len(output.strip()) < 10:  # Fixed syntax error
            return 'silent_failure'
        else:
            return 'unknown_error'
    
    def _adapt_next_strategy(self, result: Dict, current_strategy: str, failure_type: str):
        """Learn from failure and adapt next strategy"""
        adaptation = {
            'failed_strategy': current_strategy,
            'failure_type': failure_type,
            'recommendation': self._get_failure_recommendation(failure_type),
            'timestamp': str(self._get_current_time())
        }
        
        self.adaptive_strategies.append(adaptation)
        logger.info(f"🧠 Learned from failure: {failure_type} -> {adaptation['recommendation']}")
    
    def _get_failure_recommendation(self, failure_type: str) -> str:
        """Get recommendation based on failure type"""
        recommendations = {
            'syntax_error': 'try_different_interpreter_or_branch',
            'file_not_found': 'improve_file_discovery',
            'permission_error': 'fix_file_permissions',
            'missing_dependency': 'install_more_dependencies',
            'argument_error': 'modify_command_arguments',
            'timeout_error': 'reduce_timeout_or_simplify',
            'connection_error': 'verify_target_accessibility',
            'silent_failure': 'analyze_output_more_carefully',
            'unknown_error': 'try_completely_different_approach'
        }
        return recommendations.get(failure_type, 'unknown_recommendation')
    
    def _generate_failure_report(self) -> str:
        """Generate comprehensive failure report"""
        report = "🚫 Autonomous Execution Failure Report\n\n"
        
        report += f"Total strategies attempted: {len(self.execution_history)}\n"
        report += f"Total failures analyzed: {len(self.failed_attempts)}\n\n"
        
        report += "Strategy Results:\n"
        for attempt in self.execution_history:
            status = "✅ SUCCESS" if attempt['success'] else "❌ FAILED"
            report += f"  {attempt['attempt']}. {attempt['strategy']}: {status}\n"
            if not attempt['success'] and attempt['error']:
                report += f"     Error: {attempt['error'][:100]}...\n"
        
        report += "\nFailure Analysis:\n"
        failure_types = {}
        for failure in self.failed_attempts:
            analysis = failure['analysis']
            failure_types[analysis] = failure_types.get(analysis, 0) + 1
        
        for failure_type, count in failure_types.items():
            report += f"  - {failure_type}: {count} occurrences\n"
        
        report += "\nRecommendations:\n"
        report += "  - Check if target is reachable and vulnerable\n"
        report += "  - Verify CVE ID matches repository content\n"
        report += "  - Try manual execution in repository directory\n"
        report += "  - Check repository documentation for specific requirements\n"
        
        return report
    
    def _get_current_time(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _save_execution_log(self, repo_info: Dict, result: Dict):
        """Save execution log for analysis"""
        try:
            log_data = {
                'repository': repo_info['repo_name'],
                'timestamp': self._get_current_time(),
                'success': result.get('success', False),
                'execution_history': self.execution_history,
                'failed_attempts': self.failed_attempts,
                'adaptive_strategies': self.adaptive_strategies
            }
            
            log_file = self.logs_dir / f"{repo_info['owner']}_{repo_info['repo']}_execution.json"
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
                
            logger.info(f"Execution log saved to: {log_file}")
            
        except Exception as e:
            logger.warning(f"Failed to save execution log: {e}")
    
    def get_clone_location(self) -> str:
        """Get the base clone directory location"""
        return str(self.clone_base)
    
    def cleanup(self):
        """Clean up all temporary directories and files"""
        try:
            if self.base_temp_dir.exists():
                logger.info(f"Cleaning up autonomous executor directories: {self.base_temp_dir}")
                shutil.rmtree(self.base_temp_dir)
                logger.info("✅ Cleanup completed")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
    
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
            cmd = ['git', 'clone', '--depth', '1', clone_url, str(clone_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully cloned to {clone_path}")
                return {'success': True, 'output': result.stdout, 'path': clone_path}
            else:
                return {'success': False, 'output': result.stderr, 'error': 'Clone failed'}
        except Exception as e:
            return {'success': False, 'output': f'Clone error: {str(e)}', 'error': str(e)}
    
    def _clone_repository_branch(self, clone_url: str, clone_path: Path, branch: str) -> Dict[str, Any]:
        """Clone specific branch"""
        try:
            cmd = ['git', 'clone', '--depth', '1', '--branch', branch, clone_url, str(clone_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return {'success': True, 'output': result.stdout, 'path': clone_path}
            else:
                return {'success': False, 'output': result.stderr, 'error': f'Branch {branch} clone failed'}
        except Exception as e:
            return {'success': False, 'output': f'Branch clone error: {str(e)}', 'error': str(e)}
    
    def _get_repository_branches(self, repo_info: Dict) -> List[str]:
        """Get available branches"""
        try:
            api_url = f"{repo_info['api_url']}/branches"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                branches = response.json()
                return [branch['name'] for branch in branches]
        except Exception as e:
            logger.debug(f"Failed to get branches: {e}")
        return ['main', 'master']
    
    def _analyze_readme(self, repo_path: Path, cve_id: str) -> Dict[str, Any]:
        """Analyze README.md for execution instructions"""
        instructions = {
            'execution_commands': [],
            'main_files': [],
            'dependencies': [],
            'usage_examples': []
        }
        
        try:
            readme_files = []
            for pattern in ['README.md', 'readme.md', 'README.txt', 'README.rst', 'README']:
                readme_path = repo_path / pattern
                if readme_path.exists():
                    readme_files.append(readme_path)
            
            for readme_path in readme_files:
                with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self._extract_commands_from_readme(content, instructions, cve_id)
                self._extract_main_files_from_readme(content, instructions, cve_id)
                self._extract_dependencies_from_readme(content, instructions)
                
                break
            
        except Exception as e:
            logger.warning(f"Error analyzing README: {e}")
        
        return instructions
    
    def _extract_commands_from_readme(self, content: str, instructions: Dict, cve_id: str):
        """Extract execution commands from README content"""
        code_blocks = re.findall(r'```(?:python|bash|sh)?\n(.*?)```', content, re.DOTALL)
        
        for block in code_blocks:
            lines = block.strip().split('\n')
            for line in lines:
                line = line.strip()
                
                if line.startswith('python') and any(keyword in line.lower() for keyword in [cve_id.lower(), 'exploit', 'poc', '.py']):
                    instructions['execution_commands'].append({
                        'command': line,
                        'type': 'python',
                        'priority': 10
                    })
                elif line.startswith('./') and any(ext in line for ext in ['.py', '.sh']):
                    instructions['execution_commands'].append({
                        'command': line,
                        'type': 'direct',
                        'priority': 8
                    })
        
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
        pip_installs = re.findall(r'pip install ([^\n]+)', content)
        instructions['dependencies'].extend(pip_installs)
        
        if 'requirements.txt' in content:
            instructions['dependencies'].append('requirements.txt')
    
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
    
    def _execute_with_instructions(self, repo_path: Path, target_ip: str, cve_id: str, readme_instructions: Dict) -> Dict[str, Any]:
        """Execute PoC with README instructions"""
        try:
            # Create execution plan based on README + file discovery
            execution_plan = self._create_execution_plan(repo_path, cve_id, readme_instructions)
            
            if not execution_plan:
                return {'success': False, 'output': 'No executable PoC files found', 'error': 'No PoC files'}
            
            # Try executing each target until success
            for i, target in enumerate(execution_plan, 1):
                logger.info(f"Attempting execution #{i}: {target['description']}")
                
                result = self._execute_target(target, target_ip, repo_path)
                
                if result['success']:
                    logger.info(f"✓ Execution #{i} succeeded!")
                    result['executed_target'] = target
                    return result
                else:
                    logger.warning(f"✗ Execution #{i} failed: {result.get('error', 'Unknown error')}")
            
            return {
                'success': False,
                'output': f'All {len(execution_plan)} execution attempts failed',
                'error': 'All executions failed'
            }
            
        except Exception as e:
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e)}
    
    def _create_execution_plan(self, repo_path: Path, cve_id: str, readme_instructions: Dict) -> List[Dict]:
        """Create intelligent execution plan"""
        execution_plan = []
        
        # Priority 1: Commands from README
        for cmd_info in readme_instructions.get('execution_commands', []):
            command = cmd_info['command']
            
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
        discovered_files = self._deep_discover_executable_files(repo_path, cve_id)
        for file_info in discovered_files:
            execution_plan.append({
                'type': 'discovered',
                'file_path': file_info['path'],
                'description': f"Discovered file: {file_info['name']} (score: {file_info['score']})",
                'priority': file_info['score'] // 10
            })
        
        # Sort by priority and remove duplicates
        execution_plan.sort(key=lambda x: x['priority'], reverse=True)
        
        seen_files = set()
        unique_plan = []
        for target in execution_plan:
            file_str = str(target['file_path'])
            if file_str not in seen_files:
                seen_files.add(file_str)
                unique_plan.append(target)
        
        return unique_plan[:5]
    
    def _deep_discover_executable_files(self, repo_path: Path, cve_id: str) -> List[Dict]:
        """Discover PoC files automatically"""
        poc_files = []
        
        try:
            extensions = ['.py', '.sh', '.rb', '.pl', '.c', '.cpp', '.go', '.java']
            
            search_patterns = [
                cve_id.lower(),
                cve_id.replace('-', '_').lower(),
                cve_id.replace('CVE-', '').replace('cve-', ''),
                'exploit',
                'poc',
                'attack',
                'payload'
            ]
            
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in extensions:
                    file_name = file_path.name.lower()
                    
                    score = 0
                    
                    for i, pattern in enumerate(search_patterns):
                        if pattern in file_name:
                            score += (len(search_patterns) - i) * 15
                    
                    if file_path.suffix.lower() in ['.py', '.sh']:
                        score += 10
                    
                    if file_path.parent == repo_path:
                        score += 20
                    
                    if any(exclude in file_name for exclude in ['readme', 'license', 'makefile', 'dockerfile', 'requirements']):
                        score -= 30
                    
                    if score > 0:
                        poc_files.append({
                            'path': file_path,
                            'name': file_path.name,
                            'score': score
                        })
            
            poc_files.sort(key=lambda x: x['score'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error discovering PoC files: {e}")
        
        return poc_files
    
    def _execute_target(self, target: Dict, target_ip: str, repo_path: Path) -> Dict[str, Any]:
        """Execute a specific target"""
        try:
            file_path = target['file_path']
            extension = file_path.suffix.lower()
            
            if extension in ['.sh', '.py', '.rb', '.pl']:
                os.chmod(file_path, 0o755)
            
            if target['type'] == 'readme_command' and 'command_template' in target:
                cmd_template = target['command_template']
                cmd_parts = cmd_template.split()
                
                if target_ip not in cmd_template:
                    cmd_parts.append(target_ip)
                
                cmd = cmd_parts
            else:
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
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
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
            'privilege escalation', 'authentication bypassed', 'exploit completed'
        ]
        
        failure_indicators = [
            'failed', 'error', 'exception', 'not vulnerable',
            'access denied', 'connection refused', 'timeout',
            'syntaxerror', 'traceback'
        ]
        
        if any(indicator in output_lower for indicator in success_indicators):
            return True
        
        if any(indicator in output_lower for indicator in failure_indicators):
            return False
        
        if return_code == 0 and len(output.strip()) > 20:
            return True
        
        return False
    
    def __del__(self):
        """Ensure cleanup on destruction"""
        try:
            self.cleanup()
        except:
            pass
