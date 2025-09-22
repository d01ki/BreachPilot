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

class AutonomousGitPoCExecutor:
    """Autonomous Git-based PoC executor with self-healing capabilities"""
    
    def __init__(self):
        # Use configurable clone location with clear path structure
        self.base_temp_dir = Path(tempfile.gettempdir()) / "breachpilot_autonomous"
        self.clone_base = self.base_temp_dir / "repositories"
        self.logs_dir = self.base_temp_dir / "logs"
        
        # Create directory structure
        self.base_temp_dir.mkdir(exist_ok=True)
        self.clone_base.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        
        # Execution state tracking
        self.execution_history = []
        self.failed_attempts = []
        self.adaptive_strategies = []
        
        logger.info(f"Autonomous PoC Executor initialized:")
        logger.info(f"  Clone location: {self.clone_base}")
        logger.info(f"  Logs location: {self.logs_dir}")
    
    def execute_github_poc_with_autonomy(self, github_url: str, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Execute PoC with autonomous error recovery and adaptation"""
        try:
            # Extract repository info
            repo_info = self._extract_repo_info(github_url)
            if not repo_info:
                return {'success': False, 'output': 'Invalid GitHub URL', 'error': 'Invalid URL'}
            
            # Create dedicated clone directory for this repository
            repo_clone_path = self.clone_base / f"{repo_info['owner']}_{repo_info['repo']}"
            
            logger.info(f"Starting autonomous execution for {repo_info['repo_name']}")
            logger.info(f"Repository will be cloned to: {repo_clone_path}")
            
            # Autonomous execution with multiple strategies
            result = self._autonomous_execution_loop(repo_info, repo_clone_path, target_ip, cve_id)
            
            # Save execution log
            self._save_execution_log(repo_info, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Autonomous PoC execution failed: {e}")
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e)}
    
    def _autonomous_execution_loop(self, repo_info: Dict, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Autonomous execution loop with self-healing and adaptation"""
        max_attempts = 5
        current_attempt = 0
        
        # Define execution strategies in order of preference
        strategies = [
            'standard_clone_and_execute',
            'alternative_branch_strategy', 
            'deep_file_discovery',
            'adaptive_command_modification',
            'fallback_raw_execution'
        ]
        
        logger.info(f"Starting autonomous execution with {len(strategies)} strategies available")
        
        while current_attempt < max_attempts:
            current_attempt += 1
            strategy = strategies[min(current_attempt - 1, len(strategies) - 1)]
            
            logger.info(f"🤖 Autonomous attempt #{current_attempt}: {strategy}")
            
            try:
                # Execute strategy
                if strategy == 'standard_clone_and_execute':
                    result = self._strategy_standard_clone(repo_info, clone_path, target_ip, cve_id)
                elif strategy == 'alternative_branch_strategy':
                    result = self._strategy_alternative_branches(repo_info, clone_path, target_ip, cve_id)
                elif strategy == 'deep_file_discovery':
                    result = self._strategy_deep_file_discovery(clone_path, target_ip, cve_id)
                elif strategy == 'adaptive_command_modification':
                    result = self._strategy_adaptive_commands(clone_path, target_ip, cve_id)
                elif strategy == 'fallback_raw_execution':
                    result = self._strategy_raw_file_execution(clone_path, target_ip, cve_id)
                
                # Record attempt
                attempt_record = {
                    'attempt': current_attempt,
                    'strategy': strategy,
                    'success': result.get('success', False),
                    'error': result.get('error', ''),
                    'output_length': len(result.get('output', '')),
                    'return_code': result.get('return_code', -1)
                }
                self.execution_history.append(attempt_record)
                
                if result.get('success'):
                    logger.info(f"✅ SUCCESS! Strategy '{strategy}' succeeded on attempt #{current_attempt}")
                    result['autonomous_execution_info'] = {
                        'successful_strategy': strategy,
                        'attempts_needed': current_attempt,
                        'clone_location': str(clone_path),
                        'execution_history': self.execution_history
                    }
                    return result
                else:
                    logger.warning(f"❌ Strategy '{strategy}' failed: {result.get('error', 'Unknown error')}")
                    
                    # Analyze failure and adapt
                    failure_analysis = self._analyze_failure(result)
                    self.failed_attempts.append({
                        'strategy': strategy,
                        'error': result.get('error', ''),
                        'analysis': failure_analysis,
                        'attempt_number': current_attempt
                    })
                    
                    # Adapt for next attempt
                    self._adapt_next_strategy(result, strategy, failure_analysis)
                    
            except Exception as e:
                logger.error(f"💥 Strategy '{strategy}' crashed: {e}")
                self.failed_attempts.append({
                    'strategy': strategy,
                    'error': f"Strategy crashed: {str(e)}",
                    'analysis': 'strategy_crash',
                    'attempt_number': current_attempt
                })
        
        # All strategies failed - return comprehensive failure report
        logger.error(f"🚫 All {max_attempts} autonomous strategies exhausted")
        return {
            'success': False,
            'output': self._generate_failure_report(),
            'error': 'All autonomous strategies exhausted',
            'autonomous_execution_info': {
                'strategies_tried': [attempt['strategy'] for attempt in self.execution_history],
                'total_attempts': max_attempts,
                'clone_location': str(clone_path),
                'execution_history': self.execution_history,
                'failed_attempts': self.failed_attempts,
                'adaptive_strategies': self.adaptive_strategies
            }
        }
    
    def _strategy_standard_clone(self, repo_info: Dict, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Strategy 1: Standard README-guided execution"""
        logger.info("📋 Executing standard README-guided strategy")
        
        try:
            # Clean clone if exists
            if clone_path.exists():
                logger.info("Removing existing clone directory")
                shutil.rmtree(clone_path)
            
            # Clone repository
            logger.info(f"Cloning {repo_info['clone_url']}")
            clone_result = self._clone_repository(repo_info['clone_url'], clone_path)
            if not clone_result['success']:
                return clone_result
            
            # Analyze README for instructions
            logger.info("Analyzing README.md for execution instructions")
            readme_instructions = self._analyze_readme(clone_path, cve_id)
            
            # Install dependencies if specified
            if readme_instructions.get('dependencies'):
                logger.info(f"Installing {len(readme_instructions['dependencies'])} dependencies")
                self._install_dependencies(clone_path, readme_instructions)
            
            # Execute based on README + file discovery
            return self._execute_with_instructions(clone_path, target_ip, cve_id, readme_instructions)
            
        except Exception as e:
            return {'success': False, 'output': f'Standard strategy failed: {str(e)}', 'error': str(e)}
    
    def _strategy_alternative_branches(self, repo_info: Dict, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Strategy 2: Try different repository branches"""
        logger.info("🌿 Trying alternative branches strategy")
        
        try:
            # Get available branches
            branches = self._get_repository_branches(repo_info)
            logger.info(f"Found {len(branches)} branches: {branches}")
            
            # Priority order for branches
            priority_branches = ['main', 'master', 'develop', 'exploit', 'poc', 'vulnerability']
            
            # Sort branches by priority
            sorted_branches = []
            for priority in priority_branches:
                if priority in branches:
                    sorted_branches.append(priority)
            
            # Add remaining branches
            for branch in branches:
                if branch not in sorted_branches:
                    sorted_branches.append(branch)
            
            # Try top 3 branches
            for branch in sorted_branches[:3]:
                logger.info(f"🌿 Trying branch: {branch}")
                
                try:
                    # Clean and clone specific branch
                    if clone_path.exists():
                        shutil.rmtree(clone_path)
                    
                    clone_result = self._clone_repository_branch(repo_info['clone_url'], clone_path, branch)
                    if clone_result['success']:
                        readme_instructions = self._analyze_readme(clone_path, cve_id)
                        self._install_dependencies(clone_path, readme_instructions)
                        
                        result = self._execute_with_instructions(clone_path, target_ip, cve_id, readme_instructions)
                        if result['success']:
                            result['successful_branch'] = branch
                            return result
                
                except Exception as e:
                    logger.debug(f"Branch {branch} failed: {e}")
                    continue
            
            return {'success': False, 'output': f'All {len(sorted_branches[:3])} branches failed', 'error': 'No successful branch'}
            
        except Exception as e:
            return {'success': False, 'output': f'Branch strategy failed: {str(e)}', 'error': str(e)}
    
    def _strategy_deep_file_discovery(self, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Strategy 3: Deep file analysis and discovery"""
        logger.info("🔍 Executing deep file discovery strategy")
        
        try:
            if not clone_path.exists():
                return {'success': False, 'output': 'Repository not cloned', 'error': 'No repository'}
            
            # Comprehensive file analysis
            candidate_files = self._deep_discover_executable_files(clone_path, cve_id)
            logger.info(f"Discovered {len(candidate_files)} candidate files")
            
            if not candidate_files:
                return {'success': False, 'output': 'No executable candidates found', 'error': 'No candidates'}
            
            # Try each candidate with multiple execution approaches
            for i, file_info in enumerate(candidate_files[:5], 1):  # Limit to top 5
                logger.info(f"🔍 Deep execution #{i}: {file_info['name']} (score: {file_info['score']})")
                
                result = self._execute_file_with_variations(file_info, target_ip, clone_path)
                if result['success']:
                    result['discovery_method'] = 'deep_file_discovery'
                    result['file_score'] = file_info['score']
                    return result
            
            return {'success': False, 'output': f'All {len(candidate_files)} discovered files failed', 'error': 'No successful execution'}
            
        except Exception as e:
            return {'success': False, 'output': f'Deep discovery failed: {str(e)}', 'error': str(e)}
    
    def _strategy_adaptive_commands(self, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Strategy 4: Adaptive command modification"""
        logger.info("🧠 Executing adaptive command strategy")
        
        try:
            if not clone_path.exists():
                return {'success': False, 'output': 'No repository', 'error': 'No repository'}
            
            # Get adaptive fixes based on previous failures
            adaptive_fixes = self._get_adaptive_command_fixes()
            logger.info(f"Trying {len(adaptive_fixes)} adaptive command modifications")
            
            # Find best candidate file
            candidate_files = self._deep_discover_executable_files(clone_path, cve_id)
            if not candidate_files:
                return {'success': False, 'output': 'No files found', 'error': 'No files'}
            
            best_file = candidate_files[0]  # Highest scored file
            logger.info(f"Using best candidate: {best_file['name']} (score: {best_file['score']})")
            
            # Try each adaptive fix
            for i, fix in enumerate(adaptive_fixes, 1):
                logger.info(f"🧠 Adaptive fix #{i}: {fix['description']}")
                
                result = self._execute_with_command_fix(best_file, target_ip, clone_path, fix)
                if result['success']:
                    result['adaptive_fix_used'] = fix['description']
                    return result
            
            return {'success': False, 'output': 'All adaptive fixes failed', 'error': 'Adaptive fixes failed'}
            
        except Exception as e:
            return {'success': False, 'output': f'Adaptive strategy failed: {str(e)}', 'error': str(e)}
    
    def _strategy_raw_file_execution(self, clone_path: Path, target_ip: str, cve_id: str) -> Dict[str, Any]:
        """Strategy 5: Raw execution fallback"""
        logger.info("⚡ Executing raw file execution strategy")
        
        try:
            if not clone_path.exists():
                return {'success': False, 'output': 'No repository', 'error': 'No repository'}
            
            # Find all potentially executable files
            executable_files = []
            for ext in ['.py', '.sh', '.pl', '.rb', '.c']:
                files = list(clone_path.rglob(f'*{ext}'))
                executable_files.extend(files)
            
            # Filter out obviously non-exploit files
            filtered_files = []
            skip_patterns = ['test', 'setup', 'readme', '__init__', 'example', 'demo']
            
            for file_path in executable_files:
                if not any(skip in file_path.name.lower() for skip in skip_patterns):
                    filtered_files.append(file_path)
            
            logger.info(f"Found {len(filtered_files)} raw executable files")
            
            if not filtered_files:
                return {'success': False, 'output': 'No raw executable files', 'error': 'No executables'}
            
            # Try raw execution on each file
            for i, file_path in enumerate(filtered_files[:10], 1):  # Limit to top 10
                logger.info(f"⚡ Raw execution #{i}: {file_path.name}")
                
                result = self._raw_execute_file(file_path, target_ip, clone_path)
                if result['success']:
                    result['execution_method'] = 'raw_execution'
                    return result
            
            return {'success': False, 'output': f'All {len(filtered_files)} raw executions failed', 'error': 'Raw execution failed'}
            
        except Exception as e:
            return {'success': False, 'output': f'Raw execution strategy failed: {str(e)}', 'error': str(e)}
    
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
        elif result.get('return_code') == 0 but len(output.strip()) < 10:
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
    
    # Include helper methods (shortened for space - continuing with key methods)
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
    
    def __del__(self):
        """Ensure cleanup on destruction"""
        try:
            self.cleanup()
        except:
            pass
