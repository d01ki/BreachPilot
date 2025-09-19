"""
Tool Installation Checker and Auto-Installer for BreachPilot
ツールのインストール状況チェックと自動インストール
"""
import subprocess
import shutil
import os
import platform
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolChecker:
    """ペネトレーションテストツールのインストール状況チェッカー"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.tools_status = {}
        self.required_tools = {
            "essential": {
                "nmap": {
                    "command": "nmap",
                    "check_args": ["--version"],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "nmap"],
                        "darwin": ["brew", "install", "nmap"],
                        "windows": "Download from https://nmap.org/download.html"
                    },
                    "description": "Network discovery and security auditing"
                },
                "curl": {
                    "command": "curl",
                    "check_args": ["--version"],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "curl"],
                        "darwin": ["brew", "install", "curl"],
                        "windows": "Pre-installed or download from https://curl.se/"
                    },
                    "description": "Command line tool for transferring data"
                }
            },
            "optional": {
                "nikto": {
                    "command": "nikto",
                    "check_args": ["-Version"],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "nikto"],
                        "darwin": ["brew", "install", "nikto"],
                        "windows": "Download from https://github.com/sullo/nikto"
                    },
                    "description": "Web server security scanner"
                },
                "dirb": {
                    "command": "dirb",
                    "check_args": [],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "dirb"],
                        "darwin": ["brew", "install", "dirb"],
                        "windows": "Download from http://dirb.sourceforge.net/"
                    },
                    "description": "Web content scanner"
                },
                "msfconsole": {
                    "command": "msfconsole",
                    "check_args": ["--version"],
                    "install_commands": {
                        "linux": ["curl", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", "|", "sudo", "bash"],
                        "darwin": ["brew", "install", "metasploit"],
                        "windows": "Download from https://www.metasploit.com/"
                    },
                    "description": "Metasploit penetration testing framework"
                },
                "smbclient": {
                    "command": "smbclient",
                    "check_args": ["--version"],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "smbclient"],
                        "darwin": ["brew", "install", "samba"],
                        "windows": "Pre-installed"
                    },
                    "description": "SMB client for UNIX machines"
                },
                "whois": {
                    "command": "whois",
                    "check_args": ["--version"],
                    "install_commands": {
                        "linux": ["sudo", "apt-get", "install", "-y", "whois"],
                        "darwin": ["brew", "install", "whois"],
                        "windows": "Use online whois or install via Chocolatey"
                    },
                    "description": "WHOIS client"
                }
            }
        }
    
    def check_tool(self, tool_name: str, tool_config: Dict) -> Tuple[bool, str]:
        """個別ツールのインストール状況をチェック"""
        try:
            # コマンドの存在確認
            if not shutil.which(tool_config["command"]):
                return False, f"Command '{tool_config['command']}' not found in PATH"
            
            # バージョンチェックで動作確認
            if tool_config.get("check_args"):
                result = subprocess.run(
                    [tool_config["command"]] + tool_config["check_args"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    # バージョン情報を抽出
                    version_info = result.stdout.strip().split('\n')[0] if result.stdout else "Unknown version"
                    return True, f"Installed: {version_info}"
                else:
                    return False, f"Command failed: {result.stderr.strip()}"
            else:
                # バージョンチェックなしの場合は存在確認のみ
                return True, "Installed (version check not available)"
                
        except subprocess.TimeoutExpired:
            return False, "Command check timed out"
        except Exception as e:
            return False, f"Check failed: {str(e)}"
    
    def check_all_tools(self) -> Dict[str, Dict[str, any]]:
        """全ツールのインストール状況をチェック"""
        logger.info("Checking installation status of penetration testing tools...")
        
        all_tools = {**self.required_tools["essential"], **self.required_tools["optional"]}
        
        for tool_name, tool_config in all_tools.items():
            is_installed, status_msg = self.check_tool(tool_name, tool_config)
            
            self.tools_status[tool_name] = {
                "installed": is_installed,
                "status": status_msg,
                "description": tool_config["description"],
                "category": "essential" if tool_name in self.required_tools["essential"] else "optional",
                "install_command": tool_config["install_commands"].get(self.system, "Manual installation required")
            }
            
            if is_installed:
                logger.info(f"✅ {tool_name}: {status_msg}")
            else:
                logger.warning(f"❌ {tool_name}: {status_msg}")
        
        return self.tools_status
    
    def get_missing_essential_tools(self) -> List[str]:
        """必須ツールで不足しているものを取得"""
        missing = []
        for tool_name in self.required_tools["essential"]:
            if not self.tools_status.get(tool_name, {}).get("installed", False):
                missing.append(tool_name)
        return missing
    
    def get_install_instructions(self) -> Dict[str, str]:
        """インストール手順を取得"""
        instructions = {}
        
        for tool_name, status in self.tools_status.items():
            if not status["installed"]:
                install_cmd = status["install_command"]
                if isinstance(install_cmd, list):
                    instructions[tool_name] = " ".join(install_cmd)
                else:
                    instructions[tool_name] = install_cmd
        
        return instructions
    
    def generate_installation_script(self) -> str:
        """自動インストールスクリプトを生成"""
        missing_tools = [name for name, status in self.tools_status.items() if not status["installed"]]
        
        if not missing_tools:
            return "# All tools are already installed!"
        
        script_lines = [
            "#!/bin/bash",
            "# BreachPilot Tool Installation Script",
            f"# Generated for {self.system} system",
            "",
            "echo 'Installing penetration testing tools for BreachPilot...'",
            ""
        ]
        
        for tool_name in missing_tools:
            tool_status = self.tools_status[tool_name]
            install_cmd = tool_status["install_command"]
            
            script_lines.append(f"# Installing {tool_name} - {tool_status['description']}")
            
            if isinstance(install_cmd, list) and self.system in ["linux", "darwin"]:
                script_lines.append(f"echo 'Installing {tool_name}...'")
                script_lines.append(" ".join(install_cmd))
                script_lines.append("")
            else:
                script_lines.append(f"echo 'Manual installation required for {tool_name}'")
                script_lines.append(f"echo '{install_cmd}'")
                script_lines.append("")
        
        script_lines.extend([
            "echo 'Installation complete!'",
            "echo 'Please restart BreachPilot to detect newly installed tools.'"
        ])
        
        return "\n".join(script_lines)
    
    def auto_install_tools(self, tools_to_install: List[str] = None) -> Dict[str, bool]:
        """自動ツールインストール（Linuxのみ）"""
        if self.system != "linux":
            logger.warning("Auto-installation only supported on Linux systems")
            return {}
        
        if tools_to_install is None:
            tools_to_install = self.get_missing_essential_tools()
        
        installation_results = {}
        
        for tool_name in tools_to_install:
            if tool_name not in self.tools_status:
                continue
                
            tool_config = None
            for category in ["essential", "optional"]:
                if tool_name in self.required_tools[category]:
                    tool_config = self.required_tools[category][tool_name]
                    break
            
            if not tool_config:
                continue
            
            install_cmd = tool_config["install_commands"].get("linux", [])
            if not isinstance(install_cmd, list):
                installation_results[tool_name] = False
                continue
            
            try:
                logger.info(f"Installing {tool_name}...")
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                if result.returncode == 0:
                    logger.info(f"✅ Successfully installed {tool_name}")
                    installation_results[tool_name] = True
                    # 再チェック
                    is_installed, status_msg = self.check_tool(tool_name, tool_config)
                    self.tools_status[tool_name]["installed"] = is_installed
                    self.tools_status[tool_name]["status"] = status_msg
                else:
                    logger.error(f"❌ Failed to install {tool_name}: {result.stderr}")
                    installation_results[tool_name] = False
                    
            except subprocess.TimeoutExpired:
                logger.error(f"❌ Installation of {tool_name} timed out")
                installation_results[tool_name] = False
            except Exception as e:
                logger.error(f"❌ Error installing {tool_name}: {str(e)}")
                installation_results[tool_name] = False
        
        return installation_results


class SafeToolExecutor:
    """安全なツール実行クラス"""
    
    def __init__(self, tool_checker: ToolChecker):
        self.tool_checker = tool_checker
        self.safe_commands = {
            "nmap": ["nmap", "nmap-safe"],
            "curl": ["curl"],
            "whois": ["whois"],
            "nslookup": ["nslookup"],
            "ping": ["ping"]
        }
    
    def is_tool_available(self, tool_name: str) -> bool:
        """ツールが利用可能かチェック"""
        return self.tool_checker.tools_status.get(tool_name, {}).get("installed", False)
    
    async def execute_safe_command(self, command: List[str], timeout: int = 60) -> Dict[str, any]:
        """安全なコマンド実行"""
        if not command:
            return {"error": "No command provided"}
        
        tool_name = command[0]
        
        # ツールの可用性チェック
        if not self.is_tool_available(tool_name):
            return {
                "error": f"Tool '{tool_name}' is not installed or not available",
                "suggestion": f"Install {tool_name} using: {self.tool_checker.tools_status.get(tool_name, {}).get('install_command', 'Manual installation required')}"
            }
        
        # 安全性チェック
        if not self._is_safe_command(command):
            return {"error": f"Command not allowed for security reasons: {' '.join(command)}"}
        
        try:
            import asyncio
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                "status": "success",
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "returncode": process.returncode,
                "command": " ".join(command)
            }
            
        except asyncio.TimeoutError:
            return {"error": f"Command timed out after {timeout} seconds"}
        except FileNotFoundError:
            return {"error": f"Command not found: {command[0]}"}
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}
    
    def _is_safe_command(self, command: List[str]) -> bool:
        """コマンドの安全性をチェック"""
        if not command:
            return False
        
        tool_name = command[0]
        
        # 許可されたツールのみ
        if tool_name not in self.safe_commands:
            return False
        
        # 危険なオプションをチェック
        dangerous_patterns = [
            "--script", "-oA", "-oG", "--interactive",
            "rm ", "del ", "format", "mkfs", "dd if="
        ]
        
        command_str = " ".join(command)
        for pattern in dangerous_patterns:
            if pattern in command_str.lower():
                return False
        
        return True


# グローバルインスタンス
_tool_checker = None
_safe_executor = None

def get_tool_checker() -> ToolChecker:
    """ツールチェッカーのグローバルインスタンスを取得"""
    global _tool_checker
    if _tool_checker is None:
        _tool_checker = ToolChecker()
        _tool_checker.check_all_tools()
    return _tool_checker

def get_safe_executor() -> SafeToolExecutor:
    """安全なツール実行器のグローバルインスタンスを取得"""
    global _safe_executor
    if _safe_executor is None:
        _safe_executor = SafeToolExecutor(get_tool_checker())
    return _safe_executor
