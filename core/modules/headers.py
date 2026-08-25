import httpx
from typing import List, Dict, Any
from urllib.parse import urlparse
from ..models import Vulnerability, Severity, FindingEvidence

class SecurityHeadersScanner:
    def __init__(self, target_url: str, timeout: float = 8.0, user_agent: str = ""):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent

    async def scan(self, client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        
        try:
            headers = {"User-Agent": self.user_agent}
            resp = await client.get(self.target_url, headers=headers, timeout=self.timeout, follow_redirects=True)
            res_headers = {k.lower(): v for k, v in resp.headers.items()}
            is_https = self.target_url.lower().startswith("https://")

            # 1. Content-Security-Policy
            if "content-security-policy" not in res_headers:
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-001",
                    name="Missing Content-Security-Policy (CSP) Header",
                    category="Security Headers",
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    description="The server did not return a Content-Security-Policy (CSP) header. CSP is a powerful layer of defense against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
                    impact="Without CSP, the application relies solely on input sanitization to stop XSS and content injection attacks.",
                    remediation="Configure a restrictive Content-Security-Policy header, for example: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description="Content-Security-Policy header is absent from HTTP response."
                    )],
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://owasp.org/www-project-secure-headers/"]
                ))

            # 2. Strict-Transport-Security (HSTS)
            if is_https and "strict-transport-security" not in res_headers:
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-002",
                    name="Missing HTTP Strict Transport Security (HSTS)",
                    category="Transport Security",
                    severity=Severity.MEDIUM,
                    cvss_score=4.3,
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                    description="The web server does not enforce HTTPS connections using the Strict-Transport-Security header. This exposes users to SSL-stripping Man-In-The-Middle (MITM) attacks.",
                    impact="Adversaries on the same network can intercept unencrypted HTTP communications or downgrade HTTPS sessions.",
                    remediation="Add the HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description="Strict-Transport-Security header missing on HTTPS endpoint."
                    )],
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
                ))

            # 3. X-Frame-Options (Clickjacking)
            if "x-frame-options" not in res_headers and "frame-ancestors" not in res_headers.get("content-security-policy", ""):
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-003",
                    name="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    category="Security Headers",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    description="The server did not return an X-Frame-Options header or CSP frame-ancestors directive. This allows attackers to embed this website inside an invisible iframe on malicious pages.",
                    impact="Users could be tricked into clicking hidden buttons or performing unauthorized actions (Clickjacking).",
                    remediation="Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`, or use `frame-ancestors 'self'` in CSP.",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description="X-Frame-Options header is absent."
                    )],
                    references=["https://owasp.org/www-community/attacks/Clickjacking"]
                ))

            # 4. X-Content-Type-Options
            if res_headers.get("x-content-type-options", "").lower() != "nosniff":
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-004",
                    name="Missing or Ineffective X-Content-Type-Options Header",
                    category="Security Headers",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    description="The X-Content-Type-Options header is missing or not set to 'nosniff'. This may allow browsers to perform MIME-type sniffing, transforming non-executable MIME types into executable script contexts.",
                    impact="Could lead to XSS attacks if user-uploaded non-script files (like images) contain malicious HTML/script code.",
                    remediation="Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description=f"Value: '{res_headers.get('x-content-type-options', 'None')}', expected 'nosniff'."
                    )],
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
                ))

            # 5. Information Disclosure (Server / X-Powered-By)
            leaked_headers = []
            if "server" in res_headers and any(char.isdigit() for char in res_headers["server"]):
                leaked_headers.append(f"Server: {res_headers['server']}")
            if "x-powered-by" in res_headers:
                leaked_headers.append(f"X-Powered-By: {res_headers['x-powered-by']}")
            if "x-aspnet-version" in res_headers:
                leaked_headers.append(f"X-AspNet-Version: {res_headers['x-aspnet-version']}")

            if leaked_headers:
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-005",
                    name="Server Banner & Version Information Disclosure",
                    category="Information Disclosure",
                    severity=Severity.INFO,
                    cvss_score=2.0,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    description="The server leaks detailed software and version information in response headers. This assists attackers in finding targeted exploits for known version vulnerabilities.",
                    impact="Facilitates reconnaissance by attackers targeting known CVEs for the specific server or framework version.",
                    remediation="Suppress or obfuscate banner headers (e.g. set `server_tokens off;` in Nginx, `ServerSignature Off` in Apache, or remove `X-Powered-By`).",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description="Exposed banner headers: " + ", ".join(leaked_headers)
                    )],
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"]
                ))

            # 6. Permissive CORS (Access-Control-Allow-Origin: *)
            cors_origin = res_headers.get("access-control-allow-origin")
            if cors_origin == "*":
                vulnerabilities.append(Vulnerability(
                    id="SEC-HDR-006",
                    name="Overly Permissive Cross-Origin Resource Sharing (CORS) Policy",
                    category="Access Control",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                    description="The server returns `Access-Control-Allow-Origin: *`, allowing any third-party domain to read resources from this endpoint.",
                    impact="If this endpoint returns sensitive user data, malicious third-party websites can read the response via JavaScript.",
                    remediation="Restrict CORS to trusted origins only and avoid using wildcard `*` on endpoints serving sensitive data.",
                    evidence=[FindingEvidence(
                        url=str(resp.url),
                        request_method="GET",
                        response_status=resp.status_code,
                        description="Access-Control-Allow-Origin is set to wildcard '*'"
                    )],
                    references=["https://portswigger.net/web-security/cors"]
                ))

            # 7. Insecure Cookie Flags (HttpOnly / Secure / SameSite)
            for cookie_header in resp.headers.get_list("set-cookie"):
                cookie_lower = cookie_header.lower()
                cookie_name = cookie_header.split("=")[0].strip()
                missing_flags = []
                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if is_https and "secure" not in cookie_lower:
                    missing_flags.append("Secure")
                if "samesite" not in cookie_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    vulnerabilities.append(Vulnerability(
                        id=f"SEC-CK-{abs(hash(cookie_name)) % 1000:03d}",
                        name=f"Insecure Cookie Flags on '{cookie_name}'",
                        category="Session Management",
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        description=f"The cookie '{cookie_name}' is set without the following security attribute(s): {', '.join(missing_flags)}.",
                        impact="Missing HttpOnly allows JavaScript access (vulnerable to XSS session theft). Missing Secure sends cookies in plaintext. Missing SameSite exposes users to CSRF.",
                        remediation=f"Configure the cookie '{cookie_name}' with `HttpOnly; Secure; SameSite=Lax` (or `SameSite=Strict`).",
                        evidence=[FindingEvidence(
                            url=str(resp.url),
                            request_method="GET",
                            response_status=resp.status_code,
                            description=f"Set-Cookie: {cookie_header}"
                        )],
                        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
                    ))

        except Exception as e:
            pass

        return vulnerabilities
