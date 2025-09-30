"""PoC Synthesizer

Synthesizes executable PoC code from attack scenarios.
Combines templates with scenario parameters to create working exploits.
"""

import logging
import os
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import (
    AttackScenario,
    ScenarioStep,
    PoCTemplate
)

logger = logging.getLogger(__name__)


class PoCSynthesizer:
    """Synthesizes PoC code from attack scenarios"""
    
    def __init__(self, workspace_dir: Optional[Path] = None):
        if workspace_dir:
            self.workspace_dir = Path(workspace_dir)
        else:
            self.workspace_dir = Path(tempfile.mkdtemp(prefix="breachpilot_pocs_"))
        
        self.workspace_dir.mkdir(exist_ok=True, parents=True)
        logger.info(f"📦 PoC workspace: {self.workspace_dir}")
        
        self.templates = self._load_templates()
    
    def synthesize_poc(self, 
                       scenario: AttackScenario, 
                       target_ip: str) -> Dict[str, Any]:
        logger.info(f"🧪 Synthesizing PoC for scenario: {scenario.name}")
        
        synthesized_pocs = []
        
        for step in scenario.steps:
            if step.technique and self._can_synthesize(step):
                poc_data = self._synthesize_step_poc(step, target_ip, scenario)
                if poc_data:
                    synthesized_pocs.append(poc_data)
        
        master_script = self._create_master_script(
            scenario, 
            synthesized_pocs, 
            target_ip
        )
        
        result = {
            "scenario_id": scenario.scenario_id,
            "scenario_name": scenario.name,
            "pocs": synthesized_pocs,
            "master_script": master_script,
            "workspace_dir": str(self.workspace_dir),
            "total_pocs": len(synthesized_pocs)
        }
        
        logger.info(f"✅ Synthesized {len(synthesized_pocs)} PoCs for scenario")
        
        return result
    
    def _can_synthesize(self, step: ScenarioStep) -> bool:
        return step.technique in self.templates
    
    def _synthesize_step_poc(self, 
                            step: ScenarioStep, 
                            target_ip: str,
                            scenario: AttackScenario) -> Optional[Dict[str, Any]]:
        template = self.templates.get(step.technique)
        if not template:
            return None
        
        parameters = {
            "target_ip": target_ip,
            "step_number": step.step_number,
            "action": step.action,
            "tools": ", ".join(step.tools_required),
            "expected_outcome": step.expected_outcome
        }
        
        if hasattr(step, 'target_node_id'):
            parameters["target_node"] = step.target_node_id
        
        code = self._fill_template(template, parameters)
        
        filename = f"step_{step.step_number}_{step.technique.replace('.', '_')}.py"
        filepath = self.workspace_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(code)
        
        logger.info(f"📝 Created PoC: {filename}")
        
        return {
            "step_number": step.step_number,
            "technique": step.technique,
            "action": step.action,
            "filename": filename,
            "filepath": str(filepath),
            "code": code,
            "execution_command": f"python3 {filename} {target_ip}",
            "estimated_duration": step.estimated_duration,
            "success_probability": step.success_probability
        }
    
    def _fill_template(self, template: PoCTemplate, parameters: Dict[str, Any]) -> str:
        """Fill template with parameters"""
        code = template.code_template
        
        for key, value in parameters.items():
            placeholder = f"{{{{ {key} }}}}"
            code = code.replace(placeholder, str(value))
        
        return code
    
    def _create_master_script(self, 
                             scenario: AttackScenario, 
                             pocs: List[Dict[str, Any]], 
                             target_ip: str) -> Dict[str, Any]:
        """Create master execution script for the scenario"""
        
        script_lines = [
            "#!/usr/bin/env python3",
            "\"\"\"Master Attack Scenario Execution Script\"\"\"",
            "import sys",
            "import subprocess",
            "import time",
            "from datetime import datetime",
            "",
            f"# Scenario: {scenario.name}",
            f"# Target: {target_ip}",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "def log(message):",
            "    print(f'[{datetime.now().strftime(\"%H:%M:%S\")}] {message}')",
            "",
            "def execute_step(step_num, script_path, target):",
            "    log(f'Executing Step {step_num}...')",
            "    try:",
            "        result = subprocess.run(",
            "            ['python3', script_path, target],",
            "            capture_output=True,",
            "            text=True,",
            "            timeout=300",
            "        )",
            "        if result.returncode == 0:",
            "            log(f'Step {step_num} completed successfully')",
            "            return True",
            "        else:",
            "            log(f'Step {step_num} failed: {result.stderr}')",
            "            return False",
            "    except Exception as e:",
            "        log(f'Step {step_num} error: {e}')",
            "        return False",
            "",
            "def main():",
            f"    target = '{target_ip}'",
            "    log('Starting attack scenario execution')",
            "    log(f'Target: {target}')",
            ""
        ]
        
        # Add execution steps
        for poc in pocs:
            script_lines.extend([
                f"    # Step {poc['step_number']}: {poc['action']}",
                f"    if not execute_step({poc['step_number']}, '{poc['filename']}', target):",
                f"        log('Scenario failed at step {poc['step_number']}')",
                "        return 1",
                f"    time.sleep(2)  # Wait between steps",
                ""
            ])
        
        script_lines.extend([
            "    log('Scenario completed successfully')",
            "    return 0",
            "",
            "if __name__ == '__main__':",
            "    sys.exit(main())"
        ])
        
        script_content = "\n".join(script_lines)
        
        master_filename = f"execute_scenario_{scenario.scenario_id}.py"
        master_filepath = self.workspace_dir / master_filename
        
        with open(master_filepath, 'w') as f:
            f.write(script_content)
        
        # Make executable
        os.chmod(master_filepath, 0o755)
        
        logger.info(f"📜 Created master script: {master_filename}")
        
        return {
            "filename": master_filename,
            "filepath": str(master_filepath),
            "code": script_content,
            "execution_command": f"python3 {master_filename}"
        }
    
    def _load_templates(self) -> Dict[str, PoCTemplate]:
        """Load PoC templates for various techniques"""
        templates = {}
        
        # Template for Active Scanning (T1595)
        templates["T1595"] = PoCTemplate(
            template_id="t1595",
            name="Active Scanning",
            description="Verify vulnerability presence through active scanning",
            code_template="""
#!/usr/bin/env python3
import sys
import socket
import requests

target = sys.argv[1] if len(sys.argv) > 1 else '{{ target_ip }}'

print(f"[*] Scanning target: {target}")
print(f"[*] Action: {{ action }}")
print(f"[*] Expected: {{ expected_outcome }}")

# Implement scanning logic here
try:
    # Example: Port scan or version detection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex((target, 445))  # SMB port example
    if result == 0:
        print("[+] Target port is open")
        print("[+] Vulnerability presence confirmed")
        sys.exit(0)
    else:
        print("[-] Target port is closed")
        sys.exit(1)
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
finally:
    sock.close()
""",
            language="python",
            required_libraries=["socket", "requests"],
            sandbox_compatible=True
        )
        
        # Template for Exploitation (T1210)
        templates["T1210"] = PoCTemplate(
            template_id="t1210",
            name="Exploitation of Remote Services",
            description="Exploit remote service vulnerability",
            code_template="""
#!/usr/bin/env python3
import sys
import socket
import struct

target = sys.argv[1] if len(sys.argv) > 1 else '{{ target_ip }}'

print(f"[*] Exploiting target: {target}")
print(f"[*] Action: {{ action }}")
print(f"[*] Expected: {{ expected_outcome }}")

# IMPORTANT: This is a PoC template - actual exploit code would go here
# For safety, this template only performs reconnaissance

try:
    print("[*] Preparing exploit...")
    print("[*] This is a simulated exploit for testing purposes")
    print("[!] Real exploitation requires proper authorization")
    
    # Simulated exploit steps
    print("[+] Step 1: Vulnerability validation")
    print("[+] Step 2: Payload preparation")
    print("[+] Step 3: Exploit delivery")
    
    # Safety check - do not execute actual exploit
    print("[+] Exploit simulation completed")
    print("[+] In production, this would execute the actual exploit")
    
    sys.exit(0)
    
except Exception as e:
    print(f"[!] Exploit failed: {e}")
    sys.exit(1)
""",
            language="python",
            required_libraries=["socket", "struct"],
            sandbox_compatible=True,
            requires_privileges=False
        )
        
        # Template for Credential Access (T1557.001)
        templates["T1557.001"] = PoCTemplate(
            template_id="t1557_001",
            name="Man-in-the-Middle: LLMNR/NBT-NS Poisoning",
            description="NTLM relay attack template",
            code_template="""
#!/usr/bin/env python3
import sys
import subprocess

target = sys.argv[1] if len(sys.argv) > 1 else '{{ target_ip }}'

print(f"[*] Setting up NTLM relay for target: {target}")
print(f"[*] Action: {{ action }}")

# This is a safe PoC that doesn't actually perform the attack
print("[*] PoC Mode: Simulated relay attack")
print("[!] Actual relay requires tools like Responder and ntlmrelayx")
print("[!] Usage: responder -I eth0 -wrf")
print("[!] Usage: ntlmrelayx.py -tf targets.txt -smb2support")

print("[+] Relay setup simulation complete")
sys.exit(0)
""",
            language="python",
            required_libraries=[],
            sandbox_compatible=True
        )
        
        # Template for Kerberoasting (T1558.003)
        templates["T1558.003"] = PoCTemplate(
            template_id="t1558_003",
            name="Kerberoasting",
            description="Request and crack Kerberos TGS tickets",
            code_template="""
#!/usr/bin/env python3
import sys

target = sys.argv[1] if len(sys.argv) > 1 else '{{ target_ip }}'

print(f"[*] Kerberoasting target: {target}")
print(f"[*] Action: {{ action }}")

# Safe PoC - doesn't actually perform Kerberoasting
print("[*] PoC Mode: Simulated Kerberoasting")
print("[!] Actual attack requires valid domain credentials")
print("[!] Usage: GetUserSPNs.py domain/user:password -dc-ip {target} -request")

print("[+] Kerberoasting simulation complete")
sys.exit(0)
""",
            language="python",
            required_libraries=[],
            sandbox_compatible=True
        )
        
        return templates
    
    def cleanup(self):
        """Clean up workspace directory"""
        import shutil
        try:
            if self.workspace_dir.exists():
                shutil.rmtree(self.workspace_dir)
                logger.info(f"🧹 Cleaned up workspace: {self.workspace_dir}")
        except Exception as e:
            logger.error(f"Failed to cleanup workspace: {e}")