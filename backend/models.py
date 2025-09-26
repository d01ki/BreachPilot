from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    APPROVED = "approved"
    REJECTED = "rejected"

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    target_ip: Optional[str] = Field(None, description="Target IP address (legacy)")
    scan_type: str = Field(default="comprehensive", description="Type of scan to perform")
    port_range: Optional[str] = Field(default=None, description="Port range to scan")
    scan_options: Optional[Dict[str, Any]] = Field(default_factory=dict)
    enable_exploitation: bool = Field(default=False, description="Enable exploitation phase")

class NmapResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    os_detection: Optional[str] = None  # Changed to string for compatibility
    services: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    scan_time: Optional[str] = None
    raw_output: str = ""
    status: StepStatus = StepStatus.PENDING

class CVEInfo(BaseModel):
    """Professional CVE Information model"""
    cve_id: str
    description: str = ""
    severity: str = ""
    cvss_score: Optional[float] = None
    affected_service: str = ""
    exploit_available: bool = False
    cve_links: Optional[Dict[str, str]] = Field(default_factory=dict)
    technical_details: str = ""  # Professional technical analysis

class AnalystResult(BaseModel):
    """Professional analyst result"""
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    identified_cves: List[CVEInfo] = Field(default_factory=list)
    risk_assessment: str = ""
    priority_vulnerabilities: List[str] = Field(default_factory=list)
    status: StepStatus = StepStatus.PENDING

class PoCInfo(BaseModel):
    source: str
    url: str
    description: str = ""
    author: str = ""
    stars: int = 0
    code: str = ""
    filename: Optional[str] = None
    execution_command: Optional[str] = None
    file_extension: Optional[str] = None
    code_language: Optional[str] = None
    estimated_success_rate: Optional[float] = None
    requires_dependencies: bool = False
    dependencies: List[str] = Field(default_factory=list)

class PoCResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    cve_id: str
    available_pocs: List[PoCInfo] = Field(default_factory=list)
    selected_poc: Optional[PoCInfo] = None
    status: StepStatus = StepStatus.PENDING
    total_found: int = 0
    with_code: int = 0
    search_duration: Optional[float] = None

class ExploitChain(BaseModel):
    """Exploitation chain information"""
    cve_ids: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    success_probability: float = 0.0
    estimated_time: str = ""
    required_tools: List[str] = Field(default_factory=list)

class ExploitResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str = ""
    exploit_chains: List[ExploitChain] = Field(default_factory=list)
    tested_exploits: List[Dict[str, Any]] = Field(default_factory=list)
    successful_exploits: List[str] = Field(default_factory=list)
    failed_exploits: List[str] = Field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    
    # Legacy compatibility fields
    cve_id: Optional[str] = None
    exploit_used: str = ""
    execution_output: str = ""
    success: bool = False
    artifacts_captured: List[str] = Field(default_factory=list)
    poc_index: Optional[int] = None
    poc_source: Optional[str] = None
    poc_url: Optional[str] = None
    execution_time: Optional[float] = None
    execution_command: Optional[str] = None
    failure_reason: Optional[str] = None
    success_indicators: List[str] = Field(default_factory=list)
    exploit_filename: Optional[str] = None
    return_code: Optional[int] = None
    evidence: List[str] = Field(default_factory=list)
    environment_info: Optional[Dict[str, Any]] = Field(default_factory=dict)
    vulnerability_confirmed: bool = False
    exploit_successful: bool = False

class ReportResult(BaseModel):
    """Report generation result"""
    timestamp: datetime = Field(default_factory=datetime.now)
    report_path: Optional[str] = None
    pdf_path: Optional[str] = None
    html_path: Optional[str] = None
    executive_summary: str = ""
    technical_findings: str = ""
    recommendations: str = ""
    status: StepStatus = StepStatus.PENDING
    generation_time: Optional[float] = None
    errors: List[str] = Field(default_factory=list)

class ScanResult(BaseModel):
    """Complete security assessment scan result"""
    request: ScanRequest
    nmap_result: Optional[NmapResult] = None
    analyst_result: Optional[AnalystResult] = None
    exploit_result: Optional[ExploitResult] = None
    report_result: Optional[ReportResult] = None
    execution_time: float = 0.0
    status: StepStatus = StepStatus.PENDING
    errors: List[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

class ReportData(BaseModel):
    """Professional security assessment report data"""
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    report_type: str = "Professional Security Assessment"
    assessment_date: str = ""
    executive_summary: str = ""
    technical_findings: str = ""
    recommendations: str = ""
    findings_count: int = 0
    critical_issues: int = 0
    successful_exploits: int = 0
    report_url: Optional[str] = None
    pdf_url: Optional[str] = None
    nmap_result: Optional[NmapResult] = None
    analyst_result: Optional[AnalystResult] = None
    poc_results: List[PoCResult] = Field(default_factory=list)
    exploit_results: List[ExploitResult] = Field(default_factory=list)

class ScanSession(BaseModel):
    session_id: str
    target_ip: str
    created_at: datetime = Field(default_factory=datetime.now)
    current_step: str = "nmap"
    nmap_result: Optional[NmapResult] = None
    analyst_result: Optional[AnalystResult] = None
    poc_results: List[PoCResult] = Field(default_factory=list)
    exploit_results: List[ExploitResult] = Field(default_factory=list)
    report_data: Optional[ReportData] = None
