"""
Real scanning engine.
Performs genuine SSL certificate inspection, HTTP header analysis,
vulnerability detection, and performance measurement.
"""

import ssl
import socket
import time
import asyncio
import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse
from models import (
    ScanResult, SSLResult, HeadersResult,
    VulnsResult, Vulnerability, PerformanceResult
)

# ── Security headers we check for ────────────────────────────────────────────
SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}


# ── Entry point ───────────────────────────────────────────────────────────────
async def run_full_scan(url: str) -> ScanResult:
    parsed = urlparse(url)
    hostname = parsed.hostname
    is_https = parsed.scheme == "https"

    # Run checks concurrently
    ssl_task = asyncio.to_thread(check_ssl, hostname) if is_https else asyncio.to_thread(no_ssl)
    perf_task = check_performance(url)

    ssl_result, (perf_result, response_headers, status_code) = await asyncio.gather(
        ssl_task, perf_task
    )

    headers_result = analyze_headers(response_headers)
    vulns_result = detect_vulnerabilities(url, ssl_result, headers_result, response_headers, status_code)
    score = compute_score(ssl_result, headers_result, vulns_result, perf_result)

    return ScanResult(
        url=url,
        scanned_at=datetime.now(timezone.utc),
        score=score,
        ssl=ssl_result,
        headers=headers_result,
        vulnerabilities=vulns_result,
        performance=perf_result,
    )


# ── SSL Check ─────────────────────────────────────────────────────────────────
def check_ssl(hostname: str) -> SSLResult:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        # Expiry
        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expire_dt - now).days
        expired = days_left < 0

        # Issuer / subject
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
        subject_cn = subject.get("commonName", hostname)
        self_signed = issuer_name == subject.get("organizationName", "")

        # Grade
        if expired or self_signed:
            grade = "F"
        elif protocol == "TLSv1.3" and days_left > 60:
            grade = "A+"
        elif protocol in ("TLSv1.3", "TLSv1.2") and days_left > 14:
            grade = "A"
        elif days_left > 7:
            grade = "B"
        else:
            grade = "C"

        return SSLResult(
            valid=not expired,
            grade=grade,
            protocol=protocol or "Unknown",
            days_until_expiry=max(days_left, 0),
            issuer=issuer_name,
            subject=subject_cn,
            expired=expired,
            self_signed=self_signed,
        )

    except ssl.SSLCertVerificationError as e:
        return SSLResult(valid=False, grade="F", protocol="Unknown", days_until_expiry=0,
                         issuer="Unknown", subject=hostname, expired=False,
                         self_signed=False, error=f"Certificate error: {e.reason}")
    except Exception as e:
        return SSLResult(valid=False, grade="F", protocol="Unknown", days_until_expiry=0,
                         issuer="Unknown", subject=hostname, expired=False,
                         self_signed=False, error=str(e))


def no_ssl() -> SSLResult:
    return SSLResult(valid=False, grade="F", protocol="None", days_until_expiry=0,
                     issuer="N/A", subject="N/A", expired=False, self_signed=False,
                     error="Site does not use HTTPS")


# ── Performance + HTTP fetch ──────────────────────────────────────────────────
async def check_performance(url: str):
    headers = {
        "User-Agent": "Mozilla/5.0 (SiteShield Scanner/1.0; +https://siteshield.dev)"
    }
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15,
            verify=False,   # We handle SSL separately; don't block perf check on cert errors
        ) as client:
            t0 = time.monotonic()
            response = await client.get(url, headers=headers)
            total_ms = int((time.monotonic() - t0) * 1000)

        # Estimate TTFB from elapsed (httpx doesn't expose it natively without streaming)
        ttfb_ms = max(50, total_ms // 3)
        body = response.content
        size_kb = round(len(body) / 1024, 1)
        redirects = len(response.history)
        status = response.status_code

        # Score: lower is better for timing
        if total_ms < 500:
            perf_score = 95
        elif total_ms < 1000:
            perf_score = 80
        elif total_ms < 2000:
            perf_score = 65
        elif total_ms < 4000:
            perf_score = 45
        else:
            perf_score = 25

        # Penalise large pages
        if size_kb > 2000:
            perf_score -= 10
        if redirects > 2:
            perf_score -= 5

        perf_result = PerformanceResult(
            score=max(0, min(100, perf_score)),
            ttfb_ms=ttfb_ms,
            total_time_ms=total_ms,
            response_size_kb=size_kb,
            status_code=status,
            redirects=redirects,
        )
        return perf_result, dict(response.headers), status

    except Exception as e:
        perf_result = PerformanceResult(
            score=0, ttfb_ms=0, total_time_ms=0,
            response_size_kb=0, status_code=0, redirects=0,
        )
        return perf_result, {}, 0


# ── Headers Analysis ──────────────────────────────────────────────────────────
def analyze_headers(response_headers: dict) -> HeadersResult:
    lower_headers = {k.lower(): v for k, v in response_headers.items()}
    present = []
    missing = []
    details = {}

    for key, display in SECURITY_HEADERS.items():
        if key in lower_headers:
            present.append(display)
            details[display] = lower_headers[key]
        else:
            missing.append(display)
            details[display] = None

    score = round(len(present) / len(SECURITY_HEADERS) * 100)
    return HeadersResult(score=score, present=present, missing=missing, details=details)


# ── Vulnerability Detection ───────────────────────────────────────────────────
def detect_vulnerabilities(
    url: str,
    ssl: SSLResult,
    headers: HeadersResult,
    raw_headers: dict,
    status_code: int,
) -> VulnsResult:
    vulns = []
    lower_headers = {k.lower(): v for k, v in raw_headers.items()}

    # SSL issues
    if not ssl.valid or ssl.grade == "F":
        vulns.append(Vulnerability(
            severity="critical",
            title="Invalid or Missing SSL Certificate",
            description="The site is not served over HTTPS or has an invalid certificate. All traffic is unencrypted and vulnerable to interception."
        ))
    elif ssl.days_until_expiry < 14:
        vulns.append(Vulnerability(
            severity="high",
            title="SSL Certificate Expiring Soon",
            description=f"Certificate expires in {ssl.days_until_expiry} days. Renew immediately to avoid browser warnings."
        ))
    elif ssl.days_until_expiry < 30:
        vulns.append(Vulnerability(
            severity="medium",
            title="SSL Certificate Expiring in 30 Days",
            description=f"Certificate expires in {ssl.days_until_expiry} days. Plan renewal soon."
        ))

    if ssl.self_signed:
        vulns.append(Vulnerability(
            severity="high",
            title="Self-Signed Certificate",
            description="The SSL certificate is self-signed and not trusted by browsers. Use a CA-issued certificate."
        ))

    # Missing critical headers
    if "Content-Security-Policy" in headers.missing:
        vulns.append(Vulnerability(
            severity="high",
            title="Missing Content-Security-Policy",
            description="Without CSP, the site is vulnerable to Cross-Site Scripting (XSS) attacks."
        ))

    if "X-Frame-Options" in headers.missing and "content-security-policy" not in lower_headers:
        vulns.append(Vulnerability(
            severity="medium",
            title="Clickjacking Risk",
            description="Missing X-Frame-Options header. Attackers could embed this page in an iframe to trick users."
        ))

    if "Strict-Transport-Security" in headers.missing and url.startswith("https"):
        vulns.append(Vulnerability(
            severity="medium",
            title="Missing HSTS Header",
            description="Strict-Transport-Security is not set. Browsers may downgrade HTTPS connections to HTTP."
        ))

    if "X-Content-Type-Options" in headers.missing:
        vulns.append(Vulnerability(
            severity="low",
            title="Missing X-Content-Type-Options",
            description="Browsers may MIME-sniff responses, potentially executing non-script content as scripts."
        ))

    # Server version disclosure
    server = lower_headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        vulns.append(Vulnerability(
            severity="low",
            title="Server Version Disclosed",
            description=f"The Server header reveals version info ({server[:60]}), aiding targeted attacks."
        ))

    # X-Powered-By disclosure
    if "x-powered-by" in lower_headers:
        vulns.append(Vulnerability(
            severity="low",
            title="Technology Stack Disclosed",
            description=f"X-Powered-By header reveals: {lower_headers['x-powered-by']}. Remove to reduce attack surface."
        ))

    # HTTP (no HTTPS)
    if url.startswith("http://"):
        vulns.append(Vulnerability(
            severity="critical",
            title="Unencrypted HTTP Connection",
            description="The site does not use HTTPS. All data including passwords and cookies are sent in plaintext."
        ))

    if not vulns:
        vulns.append(Vulnerability(
            severity="info",
            title="No Obvious Vulnerabilities Detected",
            description="The automated scan found no critical issues. Consider a manual penetration test for deeper analysis."
        ))

    return VulnsResult(count=len([v for v in vulns if v.severity != "info"]), items=vulns)


# ── Score Computation ─────────────────────────────────────────────────────────
def compute_score(ssl: SSLResult, headers: HeadersResult, vulns: VulnsResult, perf: PerformanceResult) -> int:
    # Weights: SSL 35%, Headers 35%, Performance 20%, Vulns penalty 10%
    ssl_score = 100 if ssl.grade in ("A+", "A") else 70 if ssl.grade == "B" else 40 if ssl.grade == "C" else 0
    header_score = headers.score
    perf_score = perf.score

    base = ssl_score * 0.35 + header_score * 0.35 + perf_score * 0.20

    # Penalty for vulnerabilities
    penalties = {"critical": 20, "high": 10, "medium": 5, "low": 2}
    total_penalty = sum(penalties.get(v.severity, 0) for v in vulns.items)
    base -= min(total_penalty, 30)   # cap penalty at 30 pts

    return max(0, min(100, round(base)))
