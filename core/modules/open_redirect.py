from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
import httpx
from ..models import Vulnerability, Severity, FindingEvidence

REDIRECT_PARAMS = ["url", "redirect", "redirect_to", "next", "return", "return_to", "dest", "destination", "target", "goto", "forward", "r", "u", "link"]
TEST_REDIRECT_TARGET = "https://example.com"

class OpenRedirectScanner:
    def __init__(self, target_url: str, timeout: float = 6.0, user_agent: str = ""):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        headers = {"User-Agent": self.user_agent}

        # Check existing parameters and candidate redirect params
        test_keys = set(params.keys()) | {p for p in REDIRECT_PARAMS if p in url.lower()}
        if not test_keys:
            # Also test the base path with common redirect params if few params exist
            test_keys = {"redirect", "url", "next"}

        for key in test_keys:
            test_params = params.copy()
            test_params[key] = [TEST_REDIRECT_TARGET]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = await client.get(test_url, headers=headers, timeout=self.timeout, follow_redirects=False)
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")
                    if location.startswith(TEST_REDIRECT_TARGET) or location.startswith("//example.com"):
                        vulnerabilities.append(Vulnerability(
                            id=f"OPEN-REDIR-{abs(hash(key + url)) % 10000:04d}",
                            name=f"Open URL Redirection via '{key}' Parameter",
                            category="Redirection & Phishing",
                            severity=Severity.MEDIUM,
                            cvss_score=6.1,
                            cwe_id="CWE-601",
                            owasp_category="A01:2021-Broken Access Control",
                            description=f"The application accepts an untrusted external URL in the `{key}` parameter and redirects the user to that target (`Location: {location}`).",
                            impact="Attackers can craft convincing phishing URLs that appear to originate from the trusted target domain, tricking users into credential theft or malware download sites.",
                            remediation="Validate redirect destinations against a strict whitelist of allowed internal paths or relative URLs. Avoid allowing arbitrary external URLs.",
                            evidence=[FindingEvidence(
                                url=test_url,
                                parameter=key,
                                payload=TEST_REDIRECT_TARGET,
                                request_method="GET",
                                response_status=resp.status_code,
                                description=f"HTTP {resp.status_code} Redirect Location: {location}"
                            )],
                            references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"]
                        ))
                        break
            except Exception:
                continue

        return vulnerabilities
