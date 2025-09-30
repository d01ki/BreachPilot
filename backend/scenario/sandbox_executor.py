"""Sandbox Executor

Executes attack scenarios in isolated sandbox environments (Docker/VM).
Provides safety guardrails and evidence collection.
"""

import logging
import subprocess
import time
import json
import tempfile
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

from .models import AttackScenario, ScenarioStatus

logger = logging.getLogger(__name__)


class SandboxExecutor:
    """Executes attack scenarios in sandbox environments"""
    
    def __init__(self, 
                 sandbox_type: str = "docker",
                 allowed_targets: Optional[List[str]] = None):
        """
        Initialize sandbox executor
        
        Args:
            sandbox_type: Type of sandbox (docker, vm, local)
            allowed_targets: Whitelist of allowed target IPs/networks
        """
        self.sandbox_type = sandbox_type
        self.allowed_targets = allowed_targets or []
        self.execution_logs_dir = Path(tempfile.mkdtemp(prefix="breachpilot_logs_"))
        self.execution_logs_dir.mkdir(exist_ok=True, parents=True)
        
        logger.info(f"🔒 Sandbox executor initialized: {sandbox_type}")
        logger.info(f"📋 Execution logs: {self.execution_logs_dir}")
        
    def execute_scenario(self, 
                        scenario: AttackScenario,
                        target_ip: str,
                        synthesized_pocs: Dict[str, Any],
                        timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute attack scenario in sandbox
        
        Args:
            scenario: Attack scenario to execute
            target_ip: Target IP address
            synthesized_pocs: Synthesized PoC data
            timeout: Execution timeout in seconds
            
        Returns:
            Execution result with logs and artifacts
        """
        logger.info(f"🚀 Executing scenario in sandbox: {scenario.name}")
        
        # Safety check: Verify target is allowed
        if not self._is_target_allowed(target_ip):
            logger.error(f"❌ Target {target_ip} not in allowed list")
            return {
                "success": False,
                "error": "Target not authorized for testing",
                "safety_check_failed": True
            }
        
        # Update scenario status
        scenario.status = ScenarioStatus.EXECUTING
        scenario.execution_started_at = datetime.now()
        
        # Execute in appropriate sandbox
        if self.sandbox_type == "docker":
            result = self._execute_in_docker(scenario, target_ip, synthesized_pocs, timeout)
        elif self.sandbox_type == "vm":
            result = self._execute_in_vm(scenario, target_ip, synthesized_pocs, timeout)
        else:
            result = self._execute_local_safe(scenario, target_ip, synthesized_pocs, timeout)
        
        # Update scenario with results
        scenario.execution_completed_at = datetime.now()
        scenario.execution_success = result.get("success", False)
        scenario.execution_logs = result.get("logs", [])
        scenario.artifacts_collected = result.get("artifacts", [])
        scenario.status = ScenarioStatus.COMPLETED if result.get("success") else ScenarioStatus.FAILED
        
        logger.info(f"✅ Scenario execution completed. Success: {result.get('success')}")
        
        return result
    
    def _is_target_allowed(self, target_ip: str) -> bool:
        """
        Check if target is in allowed list
        
        CRITICAL SAFETY CHECK: Only execute against authorized targets
        """
        if not self.allowed_targets:
            logger.warning("⚠️  No allowed targets configured - execution blocked")
            return False
        
        # Check if target matches any allowed target/network
        for allowed in self.allowed_targets:
            if target_ip == allowed:
                return True
            # Could add CIDR matching here
        
        return False
    
    def _execute_in_docker(self, 
                          scenario: AttackScenario,
                          target_ip: str,
                          synthesized_pocs: Dict[str, Any],
                          timeout: int) -> Dict[str, Any]:
        """
        Execute scenario in Docker container
        
        Provides isolation and resource limits
        """
        logger.info("🐳 Executing in Docker sandbox")
        
        try:
            # Create Docker execution environment
            container_name = f"breachpilot_{scenario.scenario_id}"
            
            # Build Docker image with required tools
            dockerfile_content = self._generate_dockerfile(scenario)
            
            # Create temporary directory for Docker context
            docker_context = self.execution_logs_dir / scenario.scenario_id
            docker_context.mkdir(exist_ok=True)
            
            # Write Dockerfile
            dockerfile_path = docker_context / "Dockerfile"
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            
            # Copy PoC files to Docker context
            poc_workspace = Path(synthesized_pocs["workspace_dir"])
            for poc_file in poc_workspace.glob("*.py"):
                import shutil
                shutil.copy(poc_file, docker_context / poc_file.name)
            
            # Build Docker image
            logger.info("🔨 Building Docker image...")
            build_result = subprocess.run(
                ["docker", "build", "-t", f"breachpilot-{scenario.scenario_id}", "."],
                cwd=docker_context,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                logger.error(f"Docker build failed: {build_result.stderr}")
                return {
                    "success": False,
                    "error": "Docker build failed",
                    "logs": [build_result.stderr]
                }
            
            # Run scenario in container
            logger.info("▶️  Running scenario in container...")
            
            master_script = synthesized_pocs["master_script"]["filename"]
            
            run_result = subprocess.run(
                [
                    "docker", "run",
                    "--rm",
                    "--name", container_name,
                    "--network", "host",  # Or use custom network
                    "--cpus", "1.0",  # Resource limits
                    "--memory", "512m",
                    f"breachpilot-{scenario.scenario_id}",
                    "python3", master_script
                ],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Collect results
            logs = [
                "=== Docker Execution ===",
                run_result.stdout,
                run_result.stderr
            ]
            
            success = run_result.returncode == 0
            
            # Save logs
            self._save_execution_log(scenario.scenario_id, logs)
            
            return {
                "success": success,
                "logs": logs,
                "artifacts": [],
                "execution_time": None,
                "return_code": run_result.returncode
            }
            
        except subprocess.TimeoutExpired:
            logger.error("⏱️  Docker execution timed out")
            return {
                "success": False,
                "error": "Execution timeout",
                "logs": ["Execution exceeded timeout limit"]
            }
        except Exception as e:
            logger.error(f"Docker execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "logs": [str(e)]
            }
    
    def _execute_in_vm(self, 
                      scenario: AttackScenario,
                      target_ip: str,
                      synthesized_pocs: Dict[str, Any],
                      timeout: int) -> Dict[str, Any]:
        """
        Execute scenario in VM (Vagrant/VirtualBox)
        
        Provides full OS isolation
        """
        logger.info("💻 Executing in VM sandbox")
        
        # VM execution not implemented in this version
        # Would use Vagrant or direct VM management
        
        return {
            "success": False,
            "error": "VM execution not yet implemented",
            "logs": ["VM sandbox execution requires additional configuration"]
        }
    
    def _execute_local_safe(self, 
                           scenario: AttackScenario,
                           target_ip: str,
                           synthesized_pocs: Dict[str, Any],
                           timeout: int) -> Dict[str, Any]:
        """
        Execute scenario locally with safety restrictions
        
        ONLY FOR TESTING - Not recommended for production
        """
        logger.warning("⚠️  Executing locally (not sandboxed)")
        
        try:
            master_script = Path(synthesized_pocs["master_script"]["filepath"])
            
            logger.info(f"▶️  Running: {master_script}")
            
            result = subprocess.run(
                ["python3", str(master_script)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=master_script.parent
            )
            
            logs = [
                "=== Local Execution ===",
                result.stdout,
                result.stderr
            ]
            
            success = result.returncode == 0
            
            self._save_execution_log(scenario.scenario_id, logs)
            
            return {
                "success": success,
                "logs": logs,
                "artifacts": [],
                "execution_time": None,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Execution timeout",
                "logs": ["Execution exceeded timeout limit"]
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "logs": [str(e)]
            }
    
    def _generate_dockerfile(self, scenario: AttackScenario) -> str:
        """Generate Dockerfile for scenario execution"""
        
        # Base tools needed
        tools = list(set(scenario.required_tools))
        
        dockerfile = f"""
FROM python:3.9-slim

# Install basic tools
RUN apt-get update && apt-get install -y \\
    nmap \\
    netcat \\
    curl \\
    wget \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \\
    requests \\
    impacket \\
    pycryptodome

# Create workspace
WORKDIR /workspace

# Copy PoC files
COPY *.py /workspace/

# Make scripts executable
RUN chmod +x /workspace/*.py

# Set user (don't run as root)
RUN useradd -m -s /bin/bash pentester
USER pentester

CMD ["/bin/bash"]
"""
        
        return dockerfile
    
    def _save_execution_log(self, scenario_id: str, logs: List[str]):
        """Save execution logs to file"""
        log_file = self.execution_logs_dir / f"{scenario_id}_execution.log"
        
        with open(log_file, 'w') as f:
            f.write("\n".join(logs))
        
        logger.info(f"📝 Logs saved: {log_file}")
    
    def cleanup(self):
        """Clean up execution logs and temporary files"""
        import shutil
        try:
            if self.execution_logs_dir.exists():
                shutil.rmtree(self.execution_logs_dir)
                logger.info(f"🧹 Cleaned up execution logs")
        except Exception as e:
            logger.error(f"Failed to cleanup logs: {e}")