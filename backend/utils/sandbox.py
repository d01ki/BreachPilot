import subprocess
import os
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class SandboxExecutor:
    """Secure sandbox execution for exploits"""
    
    def __init__(self):
        self.secure_env = self._create_secure_environment()
    
    def _create_secure_environment(self) -> Dict[str, str]:
        """Create secure environment variables for sandbox execution"""
        return {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': '/tmp',
            'USER': 'breachpilot',
            'SHELL': '/bin/bash',
            'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8',
            'PYTHONPATH': '',
            'PERL5LIB': '',
            'LD_PRELOAD': '',
            'LD_LIBRARY_PATH': '',
            'RUBYLIB': '',
            'NODE_PATH': ''
        }
    
    def execute_file(self, filepath: Path, target_ip: str, extension: str) -> Dict[str, Any]:
        """Execute file based on extension with secure sandbox"""
        exec_map = {
            'py': self._execute_python,
            'sh': self._execute_shell,
            'rb': self._execute_ruby,
            'pl': self._execute_perl
        }
        
        executor = exec_map.get(extension, self._execute_generic)
        return executor(filepath, target_ip)
    
    def _execute_python(self, filepath: Path, target_ip: str) -> Dict[str, Any]:
        """Execute Python file securely"""
        patterns = [
            ['python3', str(filepath), target_ip],
            ['python3', str(filepath), '--target', target_ip],
            ['python3', str(filepath), '-t', target_ip],
            ['python3', str(filepath)]
        ]
        
        for cmd in patterns:
            result = self._run_secure_command(cmd, filepath.parent)
            if result['success'] or cmd == patterns[-1]:
                result['command_used'] = ' '.join(cmd)
                return result
        
        return {'success': False, 'output': 'All Python execution patterns failed', 'error': 'All patterns failed'}
    
    def _execute_perl(self, filepath: Path, target_ip: str) -> Dict[str, Any]:
        """Execute Perl file securely with enhanced BOM handling"""
        patterns = [
            ['perl', str(filepath), target_ip],
            ['perl', '-w', str(filepath), target_ip],
            ['perl', str(filepath)]
        ]
        
        for cmd in patterns:
            result = self._run_secure_command(cmd, filepath.parent)
            if result['success'] or cmd == patterns[-1]:
                result['command_used'] = ' '.join(cmd)
                return result
        
        return {'success': False, 'output': 'All Perl execution patterns failed', 'error': 'All patterns failed'}
    
    def _execute_shell(self, filepath: Path, target_ip: str) -> Dict[str, Any]:
        """Execute shell script securely"""
        os.chmod(filepath, 0o755)
        
        patterns = [
            ['bash', str(filepath), target_ip],
            ['bash', str(filepath)],
            ['sh', str(filepath), target_ip]
        ]
        
        for cmd in patterns:
            result = self._run_secure_command(cmd, filepath.parent)
            if result['success']:
                result['command_used'] = ' '.join(cmd)
                return result
        
        return {'success': False, 'output': 'All shell execution patterns failed', 'error': 'All patterns failed'}
    
    def _execute_ruby(self, filepath: Path, target_ip: str) -> Dict[str, Any]:
        """Execute Ruby file securely"""
        cmd = ['ruby', str(filepath), target_ip]
        result = self._run_secure_command(cmd, filepath.parent)
        result['command_used'] = ' '.join(cmd)
        return result
    
    def _execute_generic(self, filepath: Path, target_ip: str) -> Dict[str, Any]:
        """Execute generic executable securely"""
        os.chmod(filepath, 0o755)
        cmd = [str(filepath), target_ip]
        result = self._run_secure_command(cmd, filepath.parent)
        result['command_used'] = ' '.join(cmd)
        return result
    
    def _run_secure_command(self, cmd: list, cwd: Path) -> Dict[str, Any]:
        """Run command in secure sandbox environment"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=cwd,
                env=self.secure_env,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            output = result.stdout + result.stderr
            success = self._analyze_success(output, result.returncode)
            
            return {
                'success': success,
                'output': output,
                'error': result.stderr if not success else None,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Execution timed out after 120 seconds', 'error': 'Timeout', 'return_code': -1}
        except Exception as e:
            return {'success': False, 'output': f'Execution error: {str(e)}', 'error': str(e), 'return_code': -1}
    
    def _analyze_success(self, output: str, return_code: int) -> bool:
        """Analyze execution success with multiple indicators"""
        output_lower = output.lower()
        
        # Strong success indicators
        strong_success = [
            'exploit successful', 'exploitation successful', 'successfully exploited',
            'shell obtained', 'access granted', 'login successful', 'authentication bypassed',
            'privilege escalation successful', 'root access', 'admin access',
            'payload executed', 'code execution successful', 'remote code execution',
            'vulnerability confirmed', 'target is vulnerable'
        ]
        
        # Weak success indicators
        weak_success = [
            'success', 'vulnerable', 'exploited', 'compromised', 'shell', 'access',
            'connected', 'established', 'authenticated', 'bypassed', 'elevated'
        ]
        
        # Failure indicators
        failure_indicators = [
            'failed', 'error', 'timeout', 'connection refused', 'permission denied',
            'not vulnerable', 'not exploitable', 'access denied', 'authentication failed',
            'exploit failed', 'connection timeout', 'no route to host'
        ]
        
        # Count indicators
        strong_count = sum(1 for indicator in strong_success if indicator in output_lower)
        weak_count = sum(1 for indicator in weak_success if indicator in output_lower)
        failure_count = sum(1 for indicator in failure_indicators if indicator in output_lower)
        
        # Decision logic
        if strong_count > 0:
            return True
        elif weak_count > 0 and failure_count == 0 and return_code == 0:
            return True
        elif weak_count >= 2 and failure_count == 0:
            return True
        elif return_code == 0 and len(output.strip()) > 50 and failure_count == 0:
            return True
        else:
            return False
