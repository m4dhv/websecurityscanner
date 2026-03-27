from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class SSLResult(BaseModel):
    valid: bool
    grade: str                     # A+, A, B, C, F
    protocol: str                  # TLS 1.3, TLS 1.2, etc.
    days_until_expiry: int
    issuer: str
    subject: str
    expired: bool
    self_signed: bool
    error: Optional[str] = None


class HeadersResult(BaseModel):
    score: int                     # 0–100
    present: List[str]
    missing: List[str]
    details: dict                  # header -> value or None


class Vulnerability(BaseModel):
    severity: str                  # critical, high, medium, low, info
    title: str
    description: str


class VulnsResult(BaseModel):
    count: int
    items: List[Vulnerability]


class PerformanceResult(BaseModel):
    score: int
    ttfb_ms: int                   # Time to First Byte
    total_time_ms: int
    response_size_kb: float
    status_code: int
    redirects: int


class ScanResult(BaseModel):
    url: str
    scanned_at: datetime
    score: int                     # 0–100 composite
    ssl: SSLResult
    headers: HeadersResult
    vulnerabilities: VulnsResult
    performance: PerformanceResult
