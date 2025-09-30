"""Attack Scenario Models

Data models for attack graph, attack scenarios, and PoC synthesis.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from enum import Enum


class NodeType(str, Enum):
    """Type of node in the attack graph"""
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ACCESS_POINT = "access_point"
    PRIVILEGE = "privilege"
    DATA = "data"


class ScenarioStatus(str, Enum):
    """Status of attack scenario for human-in-the-loop workflow"""
    GENERATED = "generated"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackGraphNode(BaseModel):
    """Node in the attack graph representing an asset or vulnerability"""
    node_id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    
    # Network information
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    
    # Vulnerability information
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    
    # Credential information
    credential_type: Optional[str] = None
    access_level: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """Sequence of nodes representing a possible attack path"""
    path_id: str
    nodes: List[str] = Field(default_factory=list)  # Node IDs in order
    edges: List[Dict[str, str]] = Field(default_factory=list)  # {"from": node_id, "to": node_id, "action": str}
    
    # Path metrics
    total_cost: float = 0.0  # Estimated difficulty/time
    success_probability: float = 0.0
    risk_level: str = "medium"  # low, medium, high, critical
    
    # Path description
    description: str = ""
    attack_techniques: List[str] = Field(default_factory=list)  # MITRE ATT&CK techniques


class ScenarioStep(BaseModel):
    """Individual step in an attack scenario"""
    step_number: int
    action: str  # e.g., "Exploit CVE-2020-1472", "Extract credentials"
    technique: str = ""  # MITRE ATT&CK technique ID (e.g., T1210)
    
    # Target information
    target_node_id: str
    target_description: str
    
    # Execution details
    tools_required: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    expected_outcome: str = ""
    
    # PoC information
    poc_available: bool = False
    poc_url: Optional[str] = None
    execution_command: Optional[str] = None
    
    # Success criteria
    success_indicators: List[str] = Field(default_factory=list)
    estimated_duration: Optional[int] = None  # seconds
    success_probability: float = 0.5


class PoCTemplate(BaseModel):
    """Template for synthesized PoC code"""
    template_id: str
    name: str
    description: str
    
    # Code template
    code_template: str
    language: str = "python"
    required_libraries: List[str] = Field(default_factory=list)
    
    # Parameters that need to be filled
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Execution details
    execution_template: str = ""
    sandbox_compatible: bool = True
    requires_privileges: bool = False


class AttackScenario(BaseModel):
    """Complete attack scenario from reconnaissance to compromise"""
    scenario_id: str
    name: str
    description: str
    
    # Attack path
    attack_path: AttackPath
    steps: List[ScenarioStep] = Field(default_factory=list)
    
    # Scenario metadata
    created_at: datetime = Field(default_factory=datetime.now)
    status: ScenarioStatus = ScenarioStatus.GENERATED
    
    # Risk and feasibility assessment
    overall_success_probability: float = 0.0
    estimated_total_time: int = 0  # seconds
    risk_level: str = "medium"
    stealth_level: str = "medium"  # low, medium, high
    
    # Required resources
    required_tools: List[str] = Field(default_factory=list)
    required_modules: List[str] = Field(default_factory=list)
    required_credentials: List[str] = Field(default_factory=list)
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    # Human review
    reviewer_notes: str = ""
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    # Execution results
    execution_started_at: Optional[datetime] = None
    execution_completed_at: Optional[datetime] = None
    execution_success: bool = False
    execution_logs: List[str] = Field(default_factory=list)
    artifacts_collected: List[str] = Field(default_factory=list)


class AttackGraph(BaseModel):
    """Complete attack graph for a target environment"""
    graph_id: str
    target_ip: str
    created_at: datetime = Field(default_factory=datetime.now)
    
    # Graph structure
    nodes: Dict[str, AttackGraphNode] = Field(default_factory=dict)  # node_id -> node
    edges: List[Dict[str, str]] = Field(default_factory=list)  # {"from": node_id, "to": node_id, "action": str}
    
    # Analysis results
    entry_points: List[str] = Field(default_factory=list)  # Node IDs
    high_value_targets: List[str] = Field(default_factory=list)  # Node IDs
    critical_paths: List[AttackPath] = Field(default_factory=list)
    
    # Metadata
    total_nodes: int = 0
    total_vulnerabilities: int = 0
    total_services: int = 0
    
    # Generation info
    generation_time: float = 0.0  # seconds
    llm_used: bool = False
    rule_based_analysis: bool = True