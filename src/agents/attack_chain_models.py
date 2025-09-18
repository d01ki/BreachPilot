"""
BreachPilot Attack Chain Data Models
攻撃チェーンのデータモデル定義
"""
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class AttackStage(Enum):
    """攻撃ステージ定義"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    COVER_TRACKS = "cover_tracks"


class TaskStatus(Enum):
    """タスクステータス"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class AgentRole(Enum):
    """エージェントロール"""
    RECON_SPECIALIST = "recon_specialist"
    VULNERABILITY_ANALYST = "vulnerability_analyst"
    EXPLOIT_ENGINEER = "exploit_engineer"
    POST_EXPLOIT_SPECIALIST = "post_exploit_specialist"
    PERSISTENCE_EXPERT = "persistence_expert"
    COMMAND_CONTROLLER = "command_controller"


@dataclass
class AttackTask:
    """攻撃タスク定義"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    stage: AttackStage = AttackStage.RECONNAISSANCE
    agent_role: AgentRole = AgentRole.RECON_SPECIALIST
    dependencies: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 1  # 1-10, 10 being highest
    estimated_duration: int = 60  # seconds
    actual_duration: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentState:
    """エージェント状態"""
    id: str
    role: AgentRole
    status: str = "idle"  # idle, busy, error
    current_task: Optional[str] = None
    completed_tasks: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    last_activity: datetime = field(default_factory=datetime.now)


@dataclass
class AttackChain:
    """攻撃チェーン定義"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    target: str = ""
    objective: str = ""
    tasks: List[AttackTask] = field(default_factory=list)
    agent_states: Dict[str, AgentState] = field(default_factory=dict)
    shared_knowledge: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "initialized"
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
