import re
from urllib.parse import urljoin
from typing import List, Dict, Any, Tuple, Optional
import httpx
from ..models import Vulnerability, Severity, FindingEvidence

SENSITIVE_PATHS = [
    {
        "path": "/.env",
        "severity": Severity.CRITICAL,
        "cvss": 9.1,
        "cwe": "CWE-200",
        "category": "Sensitive Data Exposure",
        "name": "Exposed Environment Configuration File (.env)",
        "pattern": r"(DB_PASSWORD|DB_HOST|APP_KEY|AWS_SECRET|SECRET_KEY|DATABASE_URL)=",
        "description": "The application's `.env` configuration file is publicly accessible. This file typically contains plaintext database passwords, cryptographic secret keys, and third-party API credentials.",
        "impact": "Full application compromise, database takeover, and unauthorized cloud service access.",
        "remediation": "Block web server access to dotfiles (e.g. `location ~ /\\. { deny all; }` in Nginx) and store environment variables securely."
    },
    {
        "path": "/.git/HEAD",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "cwe": "CWE-538",
        "category": "Source Code Disclosure",
        "name": "Exposed Git Version Control Repository (.git)",
        "pattern": r"ref:\s*refs/heads/",
        "description": "The `.git` directory is exposed on the web server. Attackers can reconstruct the complete source code, commit history, and exposed credentials using tools like `git-dumper`.",
        "impact": "Complete source code leak, intellectual property theft, and discovery of hardcoded secrets.",
        "remediation": "Deny all public HTTP requests to the `.git` folder in your web server configuration."
    },
    {
        "path": "/.aws/credentials",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "cwe": "CWE-522",
        "category": "Credential Exposure",
        "name": "Exposed AWS Credentials File",
        "pattern": r"\[default\]|aws_access_key_id",
        "description": "AWS credentials file is publicly accessible on the web server.",
        "impact": "Direct unauthorized access to AWS Cloud infrastructure and services.",
        "remediation": "Remove the `.aws` directory from webroot immediately and rotate all AWS access keys."
    },
    {
        "path": "/phpinfo.php",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "cwe": "CWE-200",
        "category": "Information Disclosure",
        "name": "Exposed phpinfo() Diagnostic Page",
        "pattern": r"PHP Version|phpinfo\(\)",
        "description": "The `phpinfo()` diagnostic page is left publicly exposed. It reveals server environment variables, loaded modules, file paths, and internal network details.",
        "impact": "Aids attackers in crafting targeted exploits against the exact PHP version and extensions.",
        "remediation": "Remove all `phpinfo()` test scripts from production servers."
    },
    {
        "path": "/server-status",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "cwe": "CWE-200",
        "category": "Information Disclosure",
        "name": "Exposed Apache Server Status Page",
        "pattern": r"Apache Server Status for",
        "description": "The Apache `mod_status` page is publicly accessible, displaying active client IP addresses, requested URLs, and server load metrics.",
        "impact": "Leads to client privacy violation and reveals hidden endpoints being accessed in real time.",
        "remediation": "Restrict `/server-status` access to `127.0.0.1` or authorized internal IPs only."
    },
    {
        "path": "/robots.txt",
        "severity": Severity.INFO,
        "cvss": 2.0,
        "cwe": "CWE-200",
        "category": "Information Disclosure",
        "name": "Disallow Directives Found in robots.txt",
        "pattern": r"Disallow:\s*(/.*)",
        "description": "The `robots.txt` file specifies paths disallowed from search engine indexing, often revealing sensitive or administrative directory paths.",
        "impact": "Helps attackers discover unpublished admin portals, staging directories, or private endpoints.",
        "remediation": "Ensure disallowed paths in `robots.txt` are adequately protected by authentication and access control.",
        "extract_all": True
    },
    {
        "path": "/.gitignore",
        "severity": Severity.LOW,
        "cvss": 3.0,
        "cwe": "CWE-200",
        "category": "Information Disclosure",
        "name": "Publicly Accessible .gitignore File",
        "pattern": r"(node_modules|\.env|\.DS_Store|\*\.log)",
        "description": "The `.gitignore` file is accessible, revealing local file structures, build artifacts, and hidden project directory names.",
        "impact": "Assists attackers in fingerprinting project dependencies and directory structures.",
        "remediation": "Configure web server to deny access to dotfiles."
    },
    {
        "path": "/swagger.json",
        "severity": Severity.INFO,
        "cvss": 2.0,
        "cwe": "CWE-200",
        "category": "API Information Disclosure",
        "name": "Exposed Swagger / OpenAPI Specification File",
        "pattern": r'("swagger"|"openapi"|"paths")',
        "description": "A public Swagger / OpenAPI definition file is accessible, detailing all API endpoints, schemas, and parameter requirements.",
        "impact": "Facilitates full API enumeration and mapping of attack surfaces.",
        "remediation": "Protect API documentation endpoints behind authentication if intended for internal use only."
    }
]

class SensitiveFilesScanner:
    def __init__(self, target_url: str, timeout: float = 6.0, user_agent: str = ""):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.user_agent = user_agent

    async def scan(self, client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        headers = {"User-Agent": self.user_agent}

        for item in SENSITIVE_PATHS:
            check_url = urljoin(self.target_url + "/", item["path"].lstrip('/'))
            try:
                resp = await client.get(check_url, headers=headers, timeout=self.timeout, follow_redirects=False)
                
                if resp.status_code == 200:
                    text = resp.text
                    pattern = item.get("pattern")
                    
                    matched = True
                    snippet = ""
                    if pattern:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            start = max(0, match.start() - 20)
                            end = min(len(text), match.end() + 60)
                            snippet = text[start:end].strip()
                        else:
                            # If pattern didn't match and it's not robots.txt, might be a custom 200 soft-404
                            matched = False

                    if matched:
                        vulnerabilities.append(Vulnerability(
                            id=f"SENS-FILE-{abs(hash(item['path'])) % 10000:04d}",
                            name=item["name"],
                            category=item["category"],
                            severity=item["severity"],
                            cvss_score=item["cvss"],
                            cwe_id=item["cwe"],
                            owasp_category="A05:2021-Security Misconfiguration",
                            description=item["description"],
                            impact=item["impact"],
                            remediation=item["remediation"],
                            evidence=[FindingEvidence(
                                url=check_url,
                                request_method="GET",
                                response_status=resp.status_code,
                                response_snippet=snippet if snippet else f"HTTP 200 OK received ({len(text)} bytes).",
                                description=f"Exposed resource confirmed at {item['path']}"
                            )],
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"]
                        ))
            except Exception:
                continue

        return vulnerabilities
