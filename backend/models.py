from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    APPROVED = "approved"
    REJECTED = "rejected"

class ScanRequest(BaseModel):
    target_ip: str = Field(..., description="Target IP address")
    scan_options: Optional[Dict[str, Any]] = Field(default_factory=dict)

class OSINTResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    subdomains: List[str] = Field(default_factory=list)
    dns_info: List[str] = Field(default_factory=list)
    whois_info: Optional[Dict[str, Any]] = None
    public_services: List[Dict[str, Any]] = Field(default_factory=list)
    shodan_data: Optional[Dict[str, Any]] = None
    status: StepStatus = StepStatus.PENDING

class NmapResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    os_detection: Optional[Dict[str, Any]] = None
    services: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    raw_output: str = ""
    status: StepStatus = StepStatus.PENDING

class CVEAnalysis(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    cve_id: str
    cvss_score: Optional[float] = None
    description: str = ""
    affected_service: str = ""
    xai_explanation: str = ""
    exploit_available: bool = False
    recommendation: str = ""
    cve_links: Optional[Dict[str, str]] = Field(default_factory=dict)

class AnalystResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    identified_cves: List[CVEAnalysis] = Field(default_factory=list)
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
    # New fields for enhanced PoC management
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
    # Enhanced fields
    total_found: int = 0
    with_code: int = 0
    search_duration: Optional[float] = None

class ExploitResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    cve_id: str
    target_ip: str = ""
    exploit_used: str = ""
    execution_output: str = ""
    success: bool = False
    artifacts_captured: List[str] = Field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    # New enhanced fields for multi-PoC support
    poc_index: Optional[int] = None
    poc_source: Optional[str] = None
    poc_url: Optional[str] = None
    execution_time: Optional[float] = None
    execution_command: Optional[str] = None
    failure_reason: Optional[str] = None
    success_indicators: List[str] = Field(default_factory=list)
    exploit_filename: Optional[str] = None
    return_code: Optional[int] = None

class ReportData(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    target_ip: str
    osint_result: Optional[OSINTResult] = None
    nmap_result: Optional[NmapResult] = None
    analyst_result: Optional[AnalystResult] = None
    poc_results: List[PoCResult] = Field(default_factory=list)
    exploit_results: List[ExploitResult] = Field(default_factory=list)
    executive_summary: str = ""
    markdown_report: str = ""
    pdf_path: Optional[str] = None

class ScanSession(BaseModel):
    session_id: str
    target_ip: str
    created_at: datetime = Field(default_factory=datetime.now)
    current_step: str = "osint"
    osint_result: Optional[OSINTResult] = None
    nmap_result: Optional[NmapResult] = None
    analyst_result: Optional[AnalystResult] = None
    poc_results: List[PoCResult] = Field(default_factory=list)
    exploit_results: List[ExploitResult] = Field(default_factory=list)
    report_data: Optional[ReportData] = None
