import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from ..models import SSLInfo, Vulnerability, Severity, FindingEvidence

class SSLScanner:
    def __init__(self, target_url: str, timeout: float = 6.0):
        self.target_url = target_url
        self.timeout = timeout
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"

    async def scan(self) -> Tuple[SSLInfo, List[Vulnerability]]:
        ssl_info = SSLInfo(is_https=self.is_https)
        vulnerabilities: List[Vulnerability] = []

        if not self.is_https:
            vulnerabilities.append(Vulnerability(
                id="SSL-001",
                name="Cleartext HTTP Transmission (No HTTPS)",
                category="Cryptographic Failures",
                severity=Severity.HIGH,
                cvss_score=7.4,
                cwe_id="CWE-319",
                owasp_category="A02:2021-Cryptographic Failures",
                description="The target web application communicates over unencrypted plain HTTP. All traffic, including session cookies, passwords, and form submissions, is transmitted in cleartext.",
                impact="Man-In-The-Middle (MITM) attackers can sniff, intercept, or tamper with communications across the network.",
                remediation="Enable HTTPS with a valid TLS certificate (e.g. via Let's Encrypt) and enforce automatic HTTP-to-HTTPS 301 redirection.",
                evidence=[FindingEvidence(
                    url=self.target_url,
                    request_method="GET",
                    description="Target scheme is HTTP without encryption."
                )],
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"]
            ))
            return ssl_info, vulnerabilities

        # HTTPS inspection
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    ssl_info.valid_cert = True
                    ssl_info.protocol = f"{version} ({cipher[0]} {cipher[2]} bits)" if cipher else version
                    
                    # Issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info.issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
                    
                    # Subject
                    subj_dict = dict(x[0] for x in cert.get("subject", []))
                    ssl_info.subject = subj_dict.get("commonName") or self.hostname

                    # Expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        # Format: 'May  5 12:00:00 2026 GMT'
                        try:
                            expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            ssl_info.expires_at = expire_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            days_left = (expire_dt - datetime.utcnow()).days
                            ssl_info.days_left = days_left

                            if days_left < 0:
                                vulnerabilities.append(Vulnerability(
                                    id="SSL-002",
                                    name="Expired SSL/TLS Certificate",
                                    category="Cryptographic Failures",
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    cwe_id="CWE-295",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    description=f"The TLS certificate for {self.hostname} expired on {ssl_info.expires_at}.",
                                    impact="Browsers will display severe security warnings, blocking normal users from accessing the site.",
                                    remediation="Renew and install an active TLS certificate immediately.",
                                    evidence=[FindingEvidence(
                                        url=self.target_url,
                                        description=f"Certificate expired {abs(days_left)} days ago."
                                    )]
                                ))
                            elif days_left < 14:
                                vulnerabilities.append(Vulnerability(
                                    id="SSL-003",
                                    name="SSL/TLS Certificate Expiring Soon",
                                    category="Cryptographic Failures",
                                    severity=Severity.LOW,
                                    cvss_score=3.0,
                                    cwe_id="CWE-295",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    description=f"The TLS certificate for {self.hostname} will expire in {days_left} days ({ssl_info.expires_at}).",
                                    impact="Service disruption and security warnings if not renewed before expiration.",
                                    remediation="Renew the SSL certificate and ensure auto-renewal (e.g. Certbot cron) is configured.",
                                    evidence=[FindingEvidence(
                                        url=self.target_url,
                                        description=f"Certificate expires in {days_left} days."
                                    )]
                                ))
                        except Exception:
                            pass

        except ssl.SSLCertVerificationError as e:
            ssl_info.valid_cert = False
            vulnerabilities.append(Vulnerability(
                id="SSL-004",
                name="Invalid or Self-Signed SSL/TLS Certificate",
                category="Cryptographic Failures",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cwe_id="CWE-295",
                owasp_category="A02:2021-Cryptographic Failures",
                description=f"SSL certificate verification failed: {str(e)}",
                impact="Enables MITM attackers to impersonate the target server with rogue certificates.",
                remediation="Deploy a TLS certificate signed by a publicly trusted Certificate Authority (CA).",
                evidence=[FindingEvidence(
                    url=self.target_url,
                    description=f"Verification error: {str(e)}"
                )]
            ))
        except Exception as e:
            pass

        return ssl_info, vulnerabilities
