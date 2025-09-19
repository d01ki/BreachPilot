    async def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """ツールを実行し結果を返す（ツールチェック統合版）"""
        if tool_name not in self.tools:
            return {"error": f"Tool {tool_name} not available for {self.role.value}"}
        
        # ツールチェッカーを使用してインストール状況確認
        try:
            from src.utils.tool_checker import get_tool_checker, get_safe_executor
            tool_checker = get_tool_checker()
            safe_executor = get_safe_executor()
            
            # ツールのベースコマンドを取得
            tool = self.tools[tool_name]
            base_command = tool["cmd"].split()[0]  # コマンドの最初の部分（例：nmapコマンドからnmap）
            
            # ツールがインストールされているかチェック
            if not safe_executor.is_tool_available(base_command):
                tool_status = tool_checker.tools_status.get(base_command, {})
                return {
                    "error": f"Tool '{base_command}' is not installed",
                    "status": tool_status.get("status", "Unknown"),
                    "install_command": tool_status.get("install_command", "Manual installation required"),
                    "suggestion": f"Please install {base_command} before using this tool"
                }
            
            # コマンドを構築
            cmd = tool["cmd"].format(**kwargs)
            timeout = tool.get("timeout", 60)
            
            logger.info(f"Agent {self.id} executing: {cmd}")
            
            # 実際の環境では安全なコマンド実行
            if self._should_execute_real_command(base_command):
                command_parts = cmd.split()
                result = await safe_executor.execute_safe_command(command_parts, timeout)
                
                if "error" in result:
                    # エラーの場合はシミュレーションにフォールバック
                    logger.warning(f"Real command failed, falling back to simulation: {result['error']}")
                    result = await self._simulate_tool_execution(tool_name, **kwargs)
                else:
                    # 成功した場合は結果を解析
                    result = self._parse_tool_output(tool_name, result)
            else:
                # デモ/開発環境ではシミュレーション
                result = await self._simulate_tool_execution(tool_name, **kwargs)
            
            self.knowledge_base[f"tool_result_{tool_name}_{int(time.time())}"] = result
            return result
            
        except ImportError:
            logger.warning("Tool checker not available, using simulation mode")
            return await self._simulate_tool_execution(tool_name, **kwargs)
        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            logger.error(f"Agent {self.id}: {error_msg}")
            # エラーの場合もシミュレーションにフォールバック
            return await self._simulate_tool_execution(tool_name, **kwargs)
    
    def _should_execute_real_command(self, command: str) -> bool:
        """実際のコマンドを実行すべきかどうか判断"""
        # 環境変数で制御
        import os
        if os.getenv("BREACHPILOT_DEMO_MODE", "true").lower() == "true":
            return False
        
        # 安全なコマンドのみ実行
        safe_for_real_execution = ["nslookup", "whois", "ping"]
        return command in safe_for_real_execution
    
    def _parse_tool_output(self, tool_name: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """ツール出力を解析して構造化データに変換"""
        if "error" in raw_result:
            return raw_result
        
        stdout = raw_result.get("stdout", "")
        stderr = raw_result.get("stderr", "")
        
        if tool_name == "nmap_scan" or tool_name == "nmap_quick":
            return self._parse_nmap_output(stdout, stderr)
        elif tool_name == "dns_enum":
            return self._parse_dns_output(stdout, stderr)
        elif tool_name == "whois_lookup":
            return self._parse_whois_output(stdout, stderr)
        elif tool_name == "nikto_scan":
            return self._parse_nikto_output(stdout, stderr)
        else:
            # 基本的な解析
            return {
                "status": "success" if raw_result.get("returncode") == 0 else "error",
                "raw_output": stdout,
                "raw_error": stderr,
                "command": raw_result.get("command", ""),
                "tool": tool_name
            }
    
    def _parse_nmap_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Nmap出力を解析"""
        import re
        
        result = {
            "status": "success",
            "scan_results": {
                "open_ports": [],
                "host_status": "unknown",
                "os_detection": "unknown",
                "scan_duration": "unknown"
            },
            "raw_output": stdout
        }
        
        try:
            # ポート情報を抽出
            port_pattern = r"(\d+)\/tcp\s+open\s+(\w+)(?:\s+(.+))?"
            ports = re.findall(port_pattern, stdout)
            
            for port, service, version in ports:
                result["scan_results"]["open_ports"].append({
                    "port": int(port),
                    "service": service,
                    "version": version.strip() if version else "unknown"
                })
            
            # ホスト状態を抽出
            if "Host is up" in stdout:
                result["scan_results"]["host_status"] = "up"
            elif "Host seems down" in stdout:
                result["scan_results"]["host_status"] = "down"
            
            # OS検出結果を抽出
            os_pattern = r"Running: (.+)"
            os_match = re.search(os_pattern, stdout)
            if os_match:
                result["scan_results"]["os_detection"] = os_match.group(1).strip()
            
            # スキャン時間を抽出
            time_pattern = r"Nmap done:.+in (.+)"
            time_match = re.search(time_pattern, stdout)
            if time_match:
                result["scan_results"]["scan_duration"] = time_match.group(1).strip()
                
        except Exception as e:
            logger.warning(f"Failed to parse Nmap output: {e}")
        
        return result
    
    def _parse_dns_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """DNS出力を解析"""
        return {
            "status": "success",
            "dns_records": {
                "raw_response": stdout,
                "error": stderr if stderr else None
            }
        }
    
    def _parse_whois_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """WHOIS出力を解析"""
        return {
            "status": "success",
            "whois_data": {
                "raw_response": stdout,
                "error": stderr if stderr else None
            }
        }
    
    def _parse_nikto_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Nikto出力を解析"""
        import re
        
        result = {
            "status": "success",
            "vulnerabilities": [],
            "scan_info": {},
            "raw_output": stdout
        }
        
        try:
            # 脆弱性情報を抽出（簡単な例）
            vuln_lines = [line for line in stdout.split('\n') if '+ OSVDB-' in line or '+ CVE-' in line]
            
            for line in vuln_lines:
                result["vulnerabilities"].append({
                    "description": line.strip(),
                    "severity": "unknown"  # Niktoの出力から判定する場合はここで処理
                })
                
        except Exception as e:
            logger.warning(f"Failed to parse Nikto output: {e}")
        
        return result