"""
Tool Database and Command Registry for BreachPilot
エージェント用ツール・コマンドデータベースシステム
"""
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """ツールカテゴリ"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    EVASION = "evasion"


@dataclass
class Tool:
    """ツール定義"""
    id: str
    name: str
    category: ToolCategory
    command_template: str
    description: str
    agent_roles: List[str]  # 使用可能なエージェントロール
    required_params: List[str]  # 必須パラメータ
    optional_params: List[str]  # オプションパラメータ
    timeout: int  # タイムアウト（秒）
    prerequisites: List[str]  # 前提条件
    outputs: List[str]  # 期待される出力
    risk_level: str  # リスクレベル（low/medium/high/critical）
    examples: List[Dict[str, Any]]  # 使用例
    references: List[str]  # 参考資料


class ToolDatabase:
    """ツールデータベース管理クラス"""
    
    def __init__(self, db_path: str = "data/tools.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        self._populate_default_tools()
    
    def _init_database(self):
        """データベースを初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tools (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    command_template TEXT NOT NULL,
                    description TEXT,
                    agent_roles TEXT,  -- JSON array
                    required_params TEXT,  -- JSON array
                    optional_params TEXT,  -- JSON array
                    timeout INTEGER DEFAULT 60,
                    prerequisites TEXT,  -- JSON array
                    outputs TEXT,  -- JSON array
                    risk_level TEXT DEFAULT 'medium',
                    examples TEXT,  -- JSON array
                    references TEXT,  -- JSON array
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tool_usage_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_id TEXT NOT NULL,
                    agent_id TEXT,
                    target TEXT,
                    success BOOLEAN,
                    execution_time REAL,
                    output_size INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (tool_id) REFERENCES tools (id)
                )
            ''')
            
            conn.commit()
    
    def _populate_default_tools(self):
        """デフォルトツールを追加"""
        default_tools = [
            # RECONNAISSANCE TOOLS
            Tool(
                id="nmap_quick_scan",
                name="Nmap Quick Scan",
                category=ToolCategory.RECONNAISSANCE,
                command_template="nmap -T4 -F {target}",
                description="Fast port scan for common ports",
                agent_roles=["recon_specialist"],
                required_params=["target"],
                optional_params=["ports", "timing"],
                timeout=60,
                prerequisites=["nmap"],
                outputs=["open_ports", "services", "host_status"],
                risk_level="low",
                examples=[
                    {"command": "nmap -T4 -F 192.168.1.1", "description": "Quick scan of target"}
                ],
                references=["https://nmap.org/book/man-port-scanning-basics.html"]
            ),
            
            Tool(
                id="nmap_comprehensive_scan",
                name="Nmap Comprehensive Scan",
                category=ToolCategory.SCANNING,
                command_template="nmap -sS -sV -O -A -p 1-65535 {target}",
                description="Comprehensive port and service detection",
                agent_roles=["recon_specialist"],
                required_params=["target"],
                optional_params=["port_range", "scripts"],
                timeout=300,
                prerequisites=["nmap"],
                outputs=["open_ports", "services", "versions", "os_detection"],
                risk_level="medium",
                examples=[
                    {"command": "nmap -sS -sV -O -A -p 1-1000 192.168.1.1", "description": "Comprehensive scan"}
                ],
                references=["https://nmap.org/book/man.html"]
            ),
            
            Tool(
                id="nmap_vulnerability_scan",
                name="Nmap Vulnerability Scan",
                category=ToolCategory.VULNERABILITY_ANALYSIS,
                command_template="nmap --script vuln {target}",
                description="Vulnerability detection using NSE scripts",
                agent_roles=["vulnerability_analyst"],
                required_params=["target"],
                optional_params=["script_categories"],
                timeout=180,
                prerequisites=["nmap", "nmap-scripts"],
                outputs=["vulnerabilities", "cve_ids", "risk_ratings"],
                risk_level="medium",
                examples=[
                    {"command": "nmap --script vuln 192.168.1.1", "description": "Vulnerability scan"}
                ],
                references=["https://nmap.org/nsedoc/categories/vuln.html"]
            ),
            
            Tool(
                id="dns_enumeration",
                name="DNS Enumeration",
                category=ToolCategory.ENUMERATION,
                command_template="nslookup {target}",
                description="DNS record enumeration",
                agent_roles=["recon_specialist"],
                required_params=["target"],
                optional_params=["record_type", "dns_server"],
                timeout=30,
                prerequisites=["nslookup"],
                outputs=["dns_records", "ip_addresses", "nameservers"],
                risk_level="low",
                examples=[
                    {"command": "nslookup example.com", "description": "Basic DNS lookup"}
                ],
                references=["https://linux.die.net/man/1/nslookup"]
            ),
            
            Tool(
                id="whois_lookup",
                name="WHOIS Lookup",
                category=ToolCategory.RECONNAISSANCE,
                command_template="whois {target}",
                description="Domain registration information",
                agent_roles=["recon_specialist"],
                required_params=["target"],
                optional_params=[],
                timeout=30,
                prerequisites=["whois"],
                outputs=["registration_info", "contacts", "nameservers"],
                risk_level="low",
                examples=[
                    {"command": "whois example.com", "description": "Domain information lookup"}
                ],
                references=["https://linux.die.net/man/1/whois"]
            ),
            
            # WEB APPLICATION TOOLS
            Tool(
                id="nikto_web_scan",
                name="Nikto Web Scanner",
                category=ToolCategory.VULNERABILITY_ANALYSIS,
                command_template="nikto -h {target} -p {port}",
                description="Web server vulnerability scanner",
                agent_roles=["vulnerability_analyst"],
                required_params=["target"],
                optional_params=["port", "ssl", "timeout"],
                timeout=300,
                prerequisites=["nikto"],
                outputs=["web_vulnerabilities", "server_info", "security_headers"],
                risk_level="medium",
                examples=[
                    {"command": "nikto -h http://example.com", "description": "Web vulnerability scan"}
                ],
                references=["https://github.com/sullo/nikto"]
            ),
            
            Tool(
                id="dirb_directory_scan",
                name="Dirb Directory Scanner",
                category=ToolCategory.ENUMERATION,
                command_template="dirb {target} {wordlist}",
                description="Web directory and file brute-forcer",
                agent_roles=["recon_specialist"],
                required_params=["target"],
                optional_params=["wordlist", "extensions", "timeout"],
                timeout=300,
                prerequisites=["dirb"],
                outputs=["directories", "files", "response_codes"],
                risk_level="medium",
                examples=[
                    {"command": "dirb http://example.com", "description": "Directory enumeration"}
                ],
                references=["http://dirb.sourceforge.net/"]
            ),
            
            # SMB/NETBIOS TOOLS
            Tool(
                id="smbclient_enumeration",
                name="SMB Client Enumeration",
                category=ToolCategory.ENUMERATION,
                command_template="smbclient -L {target} -N",
                description="SMB share enumeration",
                agent_roles=["post_exploit_specialist"],
                required_params=["target"],
                optional_params=["username", "password", "domain"],
                timeout=60,
                prerequisites=["smbclient"],
                outputs=["smb_shares", "permissions", "file_listings"],
                risk_level="medium",
                examples=[
                    {"command": "smbclient -L //192.168.1.1 -N", "description": "List SMB shares"}
                ],
                references=["https://www.samba.org/samba/docs/current/man-html/smbclient.1.html"]
            ),
            
            # METASPLOIT TOOLS
            Tool(
                id="msf_auxiliary_scan",
                name="Metasploit Auxiliary Scanner",
                category=ToolCategory.SCANNING,
                command_template="msfconsole -x 'use {module}; set RHOSTS {target}; run; exit'",
                description="Metasploit auxiliary module execution",
                agent_roles=["exploit_engineer"],
                required_params=["target", "module"],
                optional_params=["options"],
                timeout=180,
                prerequisites=["metasploit-framework"],
                outputs=["scan_results", "service_info", "vulnerabilities"],
                risk_level="high",
                examples=[
                    {"command": "use auxiliary/scanner/portscan/tcp", "description": "TCP port scan"}
                ],
                references=["https://docs.metasploit.com/"]
            ),
            
            Tool(
                id="msf_exploit",
                name="Metasploit Exploit",
                category=ToolCategory.EXPLOITATION,
                command_template="msfconsole -x 'use {exploit}; set RHOSTS {target}; set PAYLOAD {payload}; exploit; exit'",
                description="Metasploit exploit execution",
                agent_roles=["exploit_engineer"],
                required_params=["target", "exploit", "payload"],
                optional_params=["options"],
                timeout=300,
                prerequisites=["metasploit-framework"],
                outputs=["session", "shell_access", "privileges"],
                risk_level="critical",
                examples=[
                    {"exploit": "exploit/windows/smb/ms17_010_eternalblue", "description": "EternalBlue exploit"}
                ],
                references=["https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-exploits.html"]
            )
        ]
        
        # デフォルトツールをデータベースに追加
        for tool in default_tools:
            self.add_tool(tool)
    
    def add_tool(self, tool: Tool):
        """ツールを追加"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO tools 
                (id, name, category, command_template, description, agent_roles, 
                 required_params, optional_params, timeout, prerequisites, outputs, 
                 risk_level, examples, references)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tool.id,
                tool.name,
                tool.category.value,
                tool.command_template,
                tool.description,
                json.dumps(tool.agent_roles),
                json.dumps(tool.required_params),
                json.dumps(tool.optional_params),
                tool.timeout,
                json.dumps(tool.prerequisites),
                json.dumps(tool.outputs),
                tool.risk_level,
                json.dumps(tool.examples),
                json.dumps(tool.references)
            ))
            conn.commit()
    
    def get_tools_by_agent_role(self, agent_role: str) -> List[Tool]:
        """エージェントロール別でツールを取得"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM tools 
                WHERE agent_roles LIKE ?
            ''', (f'%{agent_role}%',))
            
            tools = []
            for row in cursor.fetchall():
                tool = self._row_to_tool(row)
                if agent_role in tool.agent_roles:
                    tools.append(tool)
            
            return tools
    
    def get_tools_by_category(self, category: ToolCategory) -> List[Tool]:
        """カテゴリ別でツールを取得"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM tools 
                WHERE category = ?
            ''', (category.value,))
            
            return [self._row_to_tool(row) for row in cursor.fetchall()]
    
    def get_tool_by_id(self, tool_id: str) -> Optional[Tool]:
        """IDでツールを取得"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM tools WHERE id = ?
            ''', (tool_id,))
            
            row = cursor.fetchone()
            return self._row_to_tool(row) if row else None
    
    def search_tools(self, query: str) -> List[Tool]:
        """ツールを検索"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM tools 
                WHERE name LIKE ? OR description LIKE ? OR command_template LIKE ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
            
            return [self._row_to_tool(row) for row in cursor.fetchall()]
    
    def log_tool_usage(self, tool_id: str, agent_id: str, target: str, 
                      success: bool, execution_time: float, output_size: int):
        """ツール使用履歴を記録"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO tool_usage_history 
                (tool_id, agent_id, target, success, execution_time, output_size)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (tool_id, agent_id, target, success, execution_time, output_size))
            conn.commit()
    
    def get_tool_usage_stats(self, tool_id: str) -> Dict[str, Any]:
        """ツール使用統計を取得"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_uses,
                    AVG(execution_time) as avg_execution_time,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_uses,
                    AVG(output_size) as avg_output_size
                FROM tool_usage_history 
                WHERE tool_id = ?
            ''', (tool_id,))
            
            row = cursor.fetchone()
            if row:
                total_uses, avg_exec_time, successful_uses, avg_output_size = row
                return {
                    "total_uses": total_uses or 0,
                    "success_rate": (successful_uses / total_uses * 100) if total_uses > 0 else 0,
                    "avg_execution_time": avg_exec_time or 0,
                    "avg_output_size": avg_output_size or 0
                }
            return {}
    
    def _row_to_tool(self, row) -> Tool:
        """データベース行をToolオブジェクトに変換"""
        return Tool(
            id=row[0],
            name=row[1],
            category=ToolCategory(row[2]),
            command_template=row[3],
            description=row[4],
            agent_roles=json.loads(row[5]) if row[5] else [],
            required_params=json.loads(row[6]) if row[6] else [],
            optional_params=json.loads(row[7]) if row[7] else [],
            timeout=row[8],
            prerequisites=json.loads(row[9]) if row[9] else [],
            outputs=json.loads(row[10]) if row[10] else [],
            risk_level=row[11],
            examples=json.loads(row[12]) if row[12] else [],
            references=json.loads(row[13]) if row[13] else []
        )
    
    def export_tools(self, filename: str):
        """ツールをJSONファイルにエクスポート"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT * FROM tools')
            tools = [asdict(self._row_to_tool(row)) for row in cursor.fetchall()]
        
        with open(filename, 'w') as f:
            json.dump(tools, f, indent=2, default=str)
        
        logger.info(f"Exported {len(tools)} tools to {filename}")
    
    def import_tools(self, filename: str):
        """JSONファイルからツールをインポート"""
        with open(filename, 'r') as f:
            tools_data = json.load(f)
        
        for tool_data in tools_data:
            tool_data['category'] = ToolCategory(tool_data['category'])
            tool = Tool(**tool_data)
            self.add_tool(tool)
        
        logger.info(f"Imported {len(tools_data)} tools from {filename}")


# グローバルインスタンス
_tool_db = None

def get_tool_database() -> ToolDatabase:
    """ツールデータベースのグローバルインスタンスを取得"""
    global _tool_db
    if _tool_db is None:
        _tool_db = ToolDatabase()
    return _tool_db


class AgentToolManager:
    """エージェント用ツール管理クラス"""
    
    def __init__(self, agent_role: str):
        self.agent_role = agent_role
        self.tool_db = get_tool_database()
        self.available_tools = self.tool_db.get_tools_by_agent_role(agent_role)
    
    def get_available_tools(self) -> List[Tool]:
        """利用可能なツールを取得"""
        return self.available_tools
    
    def get_tools_by_category(self, category: ToolCategory) -> List[Tool]:
        """カテゴリ別のツールを取得"""
        return [tool for tool in self.available_tools if tool.category == category]
    
    def select_best_tool(self, task_objective: str, target_type: str = None) -> Optional[Tool]:
        """タスク目的に最適なツールを選択"""
        # 簡単なマッチングロジック
        objective_keywords = task_objective.lower()
        
        if "scan" in objective_keywords or "port" in objective_keywords:
            scanning_tools = self.get_tools_by_category(ToolCategory.SCANNING)
            return scanning_tools[0] if scanning_tools else None
        
        elif "vulnerability" in objective_keywords or "vuln" in objective_keywords:
            vuln_tools = self.get_tools_by_category(ToolCategory.VULNERABILITY_ANALYSIS)
            return vuln_tools[0] if vuln_tools else None
        
        elif "exploit" in objective_keywords:
            exploit_tools = self.get_tools_by_category(ToolCategory.EXPLOITATION)
            return exploit_tools[0] if exploit_tools else None
        
        elif "enumerate" in objective_keywords or "recon" in objective_keywords:
            recon_tools = self.get_tools_by_category(ToolCategory.RECONNAISSANCE)
            return recon_tools[0] if recon_tools else None
        
        # デフォルトで最初のツールを返す
        return self.available_tools[0] if self.available_tools else None
    
    def format_command(self, tool: Tool, **params) -> str:
        """ツールコマンドをフォーマット"""
        try:
            return tool.command_template.format(**params)
        except KeyError as e:
            raise ValueError(f"Missing required parameter: {e}")
    
    def validate_parameters(self, tool: Tool, params: Dict[str, Any]) -> bool:
        """パラメータの妥当性を検証"""
        for required_param in tool.required_params:
            if required_param not in params:
                return False
        return True
