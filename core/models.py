from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanProfile(str, Enum):
    QUICK = "quick"         # Headers, SSL, Tech Stack, Basic Sensitive Files
    STANDARD = "standard"   # Quick + Crawler + SQLi + XSS + Open Redirect (depth 1)
    DEEP = "deep"           # Full crawl, aggressive wordlists, comprehensive checks

class FindingEvidence(BaseModel):
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    request_method: str = "GET"
    request_headers: Optional[Dict[str, str]] = None
    response_status: Optional[int] = None
    response_snippet: Optional[str] = None
    description: str

class Vulnerability(BaseModel):
    id: str
    name: str
    category: str
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    description: str
    impact: str
    remediation: str
    evidence: List[FindingEvidence] = []
    references: List[str] = []
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class TechItem(BaseModel):
    name: str
    category: str
    version: Optional[str] = None
    icon: Optional[str] = None

class SSLInfo(BaseModel):
    is_https: bool = False
    valid_cert: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires_at: Optional[str] = None
    days_left: Optional[int] = None
    protocol: Optional[str] = None

class ScanSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_grade: str = "A+"
    risk_score: float = 0.0  # 0 to 100
    urls_crawled_count: int = 0
    duration_seconds: float = 0.0

class ScanProgress(BaseModel):
    scan_id: str
    target_url: str
    status: str  # "initializing", "crawling", "scanning", "analyzing", "generating_report", "completed", "failed"
    progress_percentage: int = 0
    current_action: str = "Idle"
    logs: List[str] = []
    findings_count: int = 0

class ScanConfig(BaseModel):
    target_url: str
    profile: ScanProfile = ScanProfile.STANDARD
    max_crawl_depth: int = 2
    max_pages: int = 15
    timeout: float = 8.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 InspireScan/1.0"
    check_headers: bool = True
    check_sqli: bool = True
    check_xss: bool = True
    check_sensitive_files: bool = True
    check_open_redirect: bool = True
    check_ssl: bool = True
    check_tech_stack: bool = True

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    start_time: str
    end_time: Optional[str] = None
    status: str
    config: ScanConfig
    summary: ScanSummary
    technologies: List[TechItem] = []
    ssl_info: Optional[SSLInfo] = None
    vulnerabilities: List[Vulnerability] = []
    crawled_urls: List[str] = []
