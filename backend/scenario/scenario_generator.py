"""Scenario Generator

Generates attack scenarios from attack graphs using LLM + rule-based approach.
Creates step-by-step attack chains with prerequisites and success probabilities.
"""

import logging
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

from .models import (
    AttackGraph,
    AttackScenario,
    ScenarioStep,
    AttackPath,
    NodeType,
    ScenarioStatus
)

logger = logging.getLogger(__name__)


class ScenarioGenerator:
    """Generates attack scenarios from attack graphs"""
    
    def __init__(self, llm: Optional[ChatOpenAI] = None):
        self.llm = llm
        self.scenario_templates = self._load_scenario_templates()
        
    def generate_scenarios(self, 
                          attack_graph: AttackGraph,
                          max_scenarios: int = 5) -> List[AttackScenario]:
        logger.info(f"🎯 Generating attack scenarios (max: {max_scenarios})")
        
        scenarios = []
        
        # 1. Generate rule-based scenarios
        rule_based_scenarios = self._generate_rule_based_scenarios(attack_graph)
        scenarios.extend(rule_based_scenarios[:max_scenarios])
        
        # 2. If LLM is available, enhance with LLM-generated scenarios
        if self.llm and len(scenarios) < max_scenarios:
            llm_scenarios = self._generate_llm_scenarios(
                attack_graph, 
                max_scenarios - len(scenarios)
            )
            scenarios.extend(llm_scenarios)
        
        # 3. Rank scenarios by feasibility and impact
        scenarios = self._rank_scenarios(scenarios)
        
        logger.info(f"✅ Generated {len(scenarios)} attack scenarios")
        
        return scenarios[:max_scenarios]
    
    def _generate_rule_based_scenarios(self, attack_graph: AttackGraph) -> List[AttackScenario]:
        scenarios = []
        
        vuln_scenarios = self._generate_vulnerability_exploitation_scenarios(attack_graph)
        scenarios.extend(vuln_scenarios)
        
        service_scenarios = self._generate_service_attack_scenarios(attack_graph)
        scenarios.extend(service_scenarios)
        
        privesc_scenarios = self._generate_privilege_escalation_scenarios(attack_graph)
        scenarios.extend(privesc_scenarios)
        
        logger.info(f"Generated {len(scenarios)} rule-based scenarios")
        return scenarios
    
    def _generate_vulnerability_exploitation_scenarios(self, 
                                                       attack_graph: AttackGraph) -> List[AttackScenario]:
        scenarios = []
        
        vuln_nodes = [node for node in attack_graph.nodes.values() 
                     if node.node_type == NodeType.VULNERABILITY]
        
        vuln_nodes.sort(key=lambda n: n.exploitability_score or 0, reverse=True)
        
        for vuln_node in vuln_nodes[:3]:
            scenario_id = self._generate_scenario_id(vuln_node.cve_id or "vuln")
            
            service_node = self._find_connected_service(attack_graph, vuln_node)
            
            attack_path = self._create_vulnerability_attack_path(
                attack_graph, vuln_node, service_node
            )
            
            steps = self._create_vulnerability_exploitation_steps(
                vuln_node, service_node, attack_graph.target_ip
            )
            
            scenario = AttackScenario(
                scenario_id=scenario_id,
                name=f"Direct Exploitation of {vuln_node.cve_id}",
                description=f"Exploit {vuln_node.cve_id} on {service_node.service_name if service_node else 'target service'} to gain initial access",
                attack_path=attack_path,
                steps=steps,
                status=ScenarioStatus.PENDING_REVIEW,
                overall_success_probability=self._calculate_scenario_probability(steps),
                estimated_total_time=self._estimate_total_time(steps),
                risk_level=self._assess_risk_level(vuln_node.cvss_score),
                required_tools=self._extract_required_tools(steps),
                mitre_techniques=self._extract_mitre_techniques(steps)
            )
            
            scenarios.append(scenario)
        
        return scenarios
    
    def _generate_service_attack_scenarios(self, attack_graph: AttackGraph) -> List[AttackScenario]:
        scenarios = []
        
        service_nodes = [node for node in attack_graph.nodes.values() 
                        if node.node_type == NodeType.SERVICE]
        
        for service_node in service_nodes:
            if service_node.service_name:
                service_lower = service_node.service_name.lower()
                
                if "smb" in service_lower:
                    scenario = self._create_smb_relay_scenario(
                        attack_graph, service_node
                    )
                    if scenario:
                        scenarios.append(scenario)
                
                if "ldap" in service_lower or "kerberos" in service_lower:
                    scenario = self._create_kerberoasting_scenario(
                        attack_graph, service_node
                    )
                    if scenario:
                        scenarios.append(scenario)
        
        return scenarios
    
    def _generate_privilege_escalation_scenarios(self, attack_graph: AttackGraph) -> List[AttackScenario]:
        scenarios = []
        
        for entry_point_id in attack_graph.entry_points[:2]:
            for target_id in attack_graph.high_value_targets[:2]:
                path = self._find_path(attack_graph, entry_point_id, target_id)
                
                if path and len(path) > 1:
                    scenario = self._create_multistep_scenario(
                        attack_graph, path, entry_point_id, target_id
                    )
                    if scenario:
                        scenarios.append(scenario)
        
        return scenarios
    
    def _create_vulnerability_exploitation_steps(self, 
                                                vuln_node: Any, 
                                                service_node: Any, 
                                                target_ip: str) -> List[ScenarioStep]:
        steps = []
        
        steps.append(ScenarioStep(
            step_number=1,
            action="Confirm vulnerability presence",
            technique="T1595",
            target_node_id=service_node.node_id if service_node else vuln_node.node_id,
            target_description=f"{service_node.service_name if service_node else 'Service'} on {target_ip}",
            tools_required=["nmap", "nessus"],
            prerequisites=[],
            expected_outcome="Vulnerability confirmed present and exploitable",
            success_indicators=["Version matches vulnerable range", "Service responds to probe"],
            estimated_duration=60,
            success_probability=0.9
        ))
        
        steps.append(ScenarioStep(
            step_number=2,
            action=f"Acquire PoC for {vuln_node.cve_id}",
            technique="T1588.006",
            target_node_id=vuln_node.node_id,
            target_description=f"PoC for {vuln_node.cve_id}",
            tools_required=["github", "exploit-db"],
            prerequisites=["Vulnerability confirmed"],
            expected_outcome="Working PoC obtained and prepared",
            poc_available=vuln_node.properties.get("exploit_available", False),
            success_indicators=["PoC code downloaded", "Dependencies installed"],
            estimated_duration=300,
            success_probability=0.8 if vuln_node.properties.get("exploit_available") else 0.5
        ))
        
        steps.append(ScenarioStep(
            step_number=3,
            action=f"Execute exploit for {vuln_node.cve_id}",
            technique="T1210",
            target_node_id=vuln_node.node_id,
            target_description=f"{vuln_node.cve_id} on {target_ip}",
            tools_required=["metasploit", "custom_exploit"],
            prerequisites=["PoC acquired", "Vulnerability confirmed"],
            expected_outcome="Remote code execution or privilege escalation achieved",
            execution_command=f"exploit.py {target_ip}",
            success_indicators=["Shell obtained", "Access granted", "Privilege escalated"],
            estimated_duration=120,
            success_probability=vuln_node.exploitability_score / 10.0 if vuln_node.exploitability_score else 0.6
        ))
        
        steps.append(ScenarioStep(
            step_number=4,
            action="Establish persistence and extract data",
            technique="T1136",
            target_node_id=vuln_node.node_id,
            target_description="Compromised system",
            tools_required=["mimikatz", "custom_tools"],
            prerequisites=["Initial access obtained"],
            expected_outcome="Persistence established, credentials extracted",
            success_indicators=["Backdoor installed", "Credentials dumped"],
            estimated_duration=300,
            success_probability=0.7
        ))
        
        return steps
    
    def _create_smb_relay_scenario(self, attack_graph: AttackGraph, service_node: Any) -> Optional[AttackScenario]:
        scenario_id = self._generate_scenario_id(f"smb_relay_{service_node.node_id}")
        
        steps = [
            ScenarioStep(
                step_number=1,
                action="Setup SMB relay listener",
                technique="T1557.001",
                target_node_id=service_node.node_id,
                target_description="SMB service",
                tools_required=["responder", "ntlmrelayx"],
                prerequisites=[],
                expected_outcome="Relay listener active",
                success_indicators=["Listener started", "Waiting for connections"],
                estimated_duration=60,
                success_probability=0.95
            ),
            ScenarioStep(
                step_number=2,
                action="Capture and relay NTLM authentication",
                technique="T1557.001",
                target_node_id=service_node.node_id,
                target_description="SMB authentication traffic",
                tools_required=["ntlmrelayx"],
                prerequisites=["Relay listener active"],
                expected_outcome="NTLM credentials relayed to target",
                success_indicators=["Authentication captured", "Relay successful"],
                estimated_duration=600,
                success_probability=0.7
            ),
            ScenarioStep(
                step_number=3,
                action="Execute commands with relayed credentials",
                technique="T1021.002",
                target_node_id=service_node.node_id,
                target_description="Target system",
                tools_required=["impacket"],
                prerequisites=["NTLM relay successful"],
                expected_outcome="Remote code execution achieved",
                success_indicators=["Commands executed", "Shell obtained"],
                estimated_duration=180,
                success_probability=0.8
            )
        ]
        
        attack_path = AttackPath(
            path_id=f"path_{scenario_id}",
            nodes=[service_node.node_id],
            description="SMB Relay Attack Chain",
            success_probability=0.7,
            risk_level="high",
            attack_techniques=["T1557.001", "T1021.002"]
        )
        
        return AttackScenario(
            scenario_id=scenario_id,
            name="SMB Relay Attack",
            description="Capture and relay NTLM authentication to gain unauthorized access",
            attack_path=attack_path,
            steps=steps,
            status=ScenarioStatus.PENDING_REVIEW,
            overall_success_probability=0.7,
            estimated_total_time=840,
            risk_level="high",
            required_tools=["responder", "ntlmrelayx", "impacket"],
            mitre_tactics=["Credential Access", "Lateral Movement"],
            mitre_techniques=["T1557.001", "T1021.002"]
        )
    
    def _create_kerberoasting_scenario(self, attack_graph: AttackGraph, service_node: Any) -> Optional[AttackScenario]:
        scenario_id = self._generate_scenario_id(f"kerberoast_{service_node.node_id}")
        
        steps = [
            ScenarioStep(
                step_number=1,
                action="Enumerate service principal names (SPNs)",
                technique="T1558.003",
                target_node_id=service_node.node_id,
                target_description="Active Directory",
                tools_required=["GetUserSPNs.py", "impacket"],
                prerequisites=["Valid domain credentials"],
                expected_outcome="List of SPNs obtained",
                success_indicators=["SPNs enumerated", "Target accounts identified"],
                estimated_duration=120,
                success_probability=0.9
            ),
            ScenarioStep(
                step_number=2,
                action="Request TGS tickets for service accounts",
                technique="T1558.003",
                target_node_id=service_node.node_id,
                target_description="Kerberos TGS",
                tools_required=["GetUserSPNs.py"],
                prerequisites=["SPNs enumerated"],
                expected_outcome="TGS tickets obtained",
                success_indicators=["Tickets downloaded", "Hashes extracted"],
                estimated_duration=180,
                success_probability=0.95
            ),
            ScenarioStep(
                step_number=3,
                action="Crack service account passwords offline",
                technique="T1110.002",
                target_node_id=service_node.node_id,
                target_description="Service account hashes",
                tools_required=["hashcat", "john"],
                prerequisites=["TGS tickets obtained"],
                expected_outcome="Service account passwords cracked",
                success_indicators=["Password cracked", "Plaintext obtained"],
                estimated_duration=3600,
                success_probability=0.6
            )
        ]
        
        attack_path = AttackPath(
            path_id=f"path_{scenario_id}",
            nodes=[service_node.node_id],
            description="Kerberoasting Attack Chain",
            success_probability=0.65,
            risk_level="high",
            attack_techniques=["T1558.003", "T1110.002"]
        )
        
        return AttackScenario(
            scenario_id=scenario_id,
            name="Kerberoasting Attack",
            description="Extract and crack service account credentials from Kerberos tickets",
            attack_path=attack_path,
            steps=steps,
            status=ScenarioStatus.PENDING_REVIEW,
            overall_success_probability=0.65,
            estimated_total_time=3900,
            risk_level="high",
            required_tools=["impacket", "hashcat", "john"],
            mitre_tactics=["Credential Access"],
            mitre_techniques=["T1558.003", "T1110.002"]
        )
    
    def _find_connected_service(self, attack_graph: AttackGraph, vuln_node: Any) -> Any:
        for edge in attack_graph.edges:
            if edge["to"] == vuln_node.node_id and edge["action"] == "has_vulnerability":
                return attack_graph.nodes.get(edge["from"])
        return None
    
    def _create_vulnerability_attack_path(self, attack_graph: AttackGraph, vuln_node: Any, service_node: Any) -> AttackPath:
        path_id = self._generate_path_id(vuln_node.cve_id or "vuln")
        
        nodes = []
        if service_node:
            nodes.append(service_node.node_id)
        nodes.append(vuln_node.node_id)
        
        return AttackPath(
            path_id=path_id,
            nodes=nodes,
            description=f"Exploitation path for {vuln_node.cve_id}",
            success_probability=vuln_node.exploitability_score / 10.0 if vuln_node.exploitability_score else 0.5,
            risk_level=self._assess_risk_level(vuln_node.cvss_score),
            attack_techniques=["T1210"]
        )
    
    def _find_path(self, attack_graph: AttackGraph, start_id: str, end_id: str) -> Optional[List[str]]:
        visited = set()
        queue = [[start_id]]
        
        while queue:
            path = queue.pop(0)
            node = path[-1]
            
            if node == end_id:
                return path
            
            if node in visited:
                continue
            
            visited.add(node)
            
            for edge in attack_graph.edges:
                if edge["from"] == node and edge["to"] not in visited:
                    new_path = path + [edge["to"]]
                    queue.append(new_path)
        
        return None
    
    def _create_multistep_scenario(self, attack_graph: AttackGraph, path: List[str], entry_id: str, target_id: str) -> Optional[AttackScenario]:
        scenario_id = self._generate_scenario_id(f"multistep_{entry_id}_{target_id}")
        
        entry_node = attack_graph.nodes.get(entry_id)
        target_node = attack_graph.nodes.get(target_id)
        
        if not entry_node or not target_node:
            return None
        
        steps = []
        for i, node_id in enumerate(path):
            node = attack_graph.nodes.get(node_id)
            if node:
                step = ScenarioStep(
                    step_number=i + 1,
                    action=f"Compromise {node.label}",
                    technique="T1210",
                    target_node_id=node_id,
                    target_description=node.label,
                    tools_required=["metasploit", "custom_tools"],
                    prerequisites=[f"Step {i} completed"] if i > 0 else [],
                    expected_outcome=f"{node.label} compromised",
                    success_indicators=["Access gained"],
                    estimated_duration=300,
                    success_probability=0.7
                )
                steps.append(step)
        
        attack_path = AttackPath(
            path_id=f"path_{scenario_id}",
            nodes=path,
            description=f"Multi-step attack from {entry_node.label} to {target_node.label}",
            success_probability=0.5,
            risk_level="high"
        )
        
        return AttackScenario(
            scenario_id=scenario_id,
            name=f"Multi-Step Attack: {entry_node.label} → {target_node.label}",
            description=f"Chain attack from {entry_node.label} to reach {target_node.label}",
            attack_path=attack_path,
            steps=steps,
            status=ScenarioStatus.PENDING_REVIEW,
            overall_success_probability=0.5,
            estimated_total_time=len(steps) * 300,
            risk_level="high",
            required_tools=["metasploit", "custom_tools"]
        )
    
    def _rank_scenarios(self, scenarios: List[AttackScenario]) -> List[AttackScenario]:
        def score_scenario(scenario: AttackScenario) -> float:
            prob_score = scenario.overall_success_probability * 10
            time_score = max(0, 10 - (scenario.estimated_total_time / 1800))
            risk_map = {"critical": 10, "high": 7, "medium": 5, "low": 3}
            risk_score = risk_map.get(scenario.risk_level, 5)
            return prob_score + time_score + risk_score
        
        scenarios.sort(key=score_scenario, reverse=True)
        return scenarios
    
    def _calculate_scenario_probability(self, steps: List[ScenarioStep]) -> float:
        if not steps:
            return 0.0
        total_prob = 1.0
        for step in steps:
            total_prob *= step.success_probability
        return round(total_prob, 2)
    
    def _estimate_total_time(self, steps: List[ScenarioStep]) -> int:
        return sum(step.estimated_duration or 0 for step in steps)
    
    def _assess_risk_level(self, cvss_score: Optional[float]) -> str:
        if not cvss_score:
            return "medium"
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        return "low"
    
    def _extract_required_tools(self, steps: List[ScenarioStep]) -> List[str]:
        tools = set()
        for step in steps:
            tools.update(step.tools_required)
        return list(tools)
    
    def _extract_mitre_techniques(self, steps: List[ScenarioStep]) -> List[str]:
        techniques = set()
        for step in steps:
            if step.technique:
                techniques.add(step.technique)
        return list(techniques)
    
    def _generate_scenario_id(self, base: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hash_suffix = hashlib.md5(f"{base}{timestamp}".encode()).hexdigest()[:8]
        return f"scenario_{hash_suffix}"
    
    def _generate_path_id(self, base: str) -> str:
        hash_suffix = hashlib.md5(base.encode()).hexdigest()[:8]
        return f"path_{hash_suffix}"
    
    def _load_scenario_templates(self) -> Dict[str, Any]:
        return {}
    
    def _generate_llm_scenarios(self, attack_graph: AttackGraph, count: int) -> List[AttackScenario]:
        return []
    
    def _summarize_graph_for_llm(self, attack_graph: AttackGraph) -> str:
        return f"Target: {attack_graph.target_ip}\nNodes: {attack_graph.total_nodes}\nVulnerabilities: {attack_graph.total_vulnerabilities}"
    
    def _parse_llm_scenarios(self, response: str, attack_graph: AttackGraph) -> List[AttackScenario]:
        return []