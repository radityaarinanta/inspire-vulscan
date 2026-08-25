import re
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
import httpx
from ..models import Vulnerability, Severity, FindingEvidence

XSS_PAYLOADS = [
    ('"><script>/*Inspire*/alert(1)</script>', r'<script>/\*Inspire\*/alert\(1\)</script>', "Script tag injection"),
    ('"><img src=x onerror=alert("Inspire")>', r'<img\s+src=x\s+onerror=alert\("Inspire"\)>', "IMG tag onerror event handler"),
    ('"><svg/onload=alert("Inspire")>', r'<svg/onload=alert\("Inspire"\)>', "SVG onload event handler"),
    ('\'"><svg onload=alert(1)>', r'<svg\s+onload=alert\(1\)>', "Attribute breakout with SVG"),
    ('<inspire_xss_probe_991>', r'<inspire_xss_probe_991>', "Custom HTML tag reflection probe")
]

class XSSScanner:
    def __init__(self, target_url: str, timeout: float = 8.0, user_agent: str = ""):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent

    def _is_reflected_unescaped(self, response_text: str, regex_pattern: str) -> bool:
        return bool(re.search(regex_pattern, response_text, re.IGNORECASE))

    def _extract_evidence_snippet(self, response_text: str, regex_pattern: str) -> str:
        match = re.search(regex_pattern, response_text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 40)
            end = min(len(response_text), match.end() + 40)
            return html.escape(response_text[start:end].strip())
        return ""

    async def scan_url_params(self, url: str, client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulnerabilities

        headers = {"User-Agent": self.user_agent}

        for param_name, param_values in params.items():
            for payload, pattern, desc in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                try:
                    resp = await client.get(test_url, headers=headers, timeout=self.timeout)
                    if self._is_reflected_unescaped(resp.text, pattern):
                        snippet = self._extract_evidence_snippet(resp.text, pattern)
                        vulnerabilities.append(Vulnerability(
                            id=f"XSS-REF-{abs(hash(param_name + url)) % 10000:04d}",
                            name=f"Reflected Cross-Site Scripting (XSS) in '{param_name}'",
                            category="Cross-Site Scripting (XSS)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            description=f"Reflected Cross-Site Scripting was identified in parameter `{param_name}` on `{url}`. User-supplied input was reflected in the HTTP response without proper HTML sanitization or entity encoding.",
                            impact="Attackers can execute arbitrary JavaScript in victim browsers, leading to session hijacking (stealing session tokens/cookies), keystroke logging, credential harvesting, or defacement.",
                            remediation="Context-aware encode all user inputs before rendering into HTML (e.g., using `htmlspecialchars()` in PHP, `DOMPurify` in JS, or built-in template auto-escaping). Implement a strict Content-Security-Policy (CSP).",
                            evidence=[FindingEvidence(
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                request_method="GET",
                                response_status=resp.status_code,
                                response_snippet=snippet,
                                description=f"Unescaped reflection verified: {desc}"
                            )],
                            references=["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
                        ))
                        break  # Found XSS on this param
                except Exception:
                    continue

        return vulnerabilities

    async def scan_form(self, form: Dict[str, Any], client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        action_url = form.get("action_url")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        headers = {"User-Agent": self.user_agent}

        if not inputs or not action_url:
            return vulnerabilities

        for inp in inputs:
            inp_name = inp.get("name")
            if not inp_name or inp.get("type") in ["submit", "button", "image", "hidden"]:
                continue

            for payload, pattern, desc in XSS_PAYLOADS[:3]:
                form_data = {item.get("name"): item.get("value", "") for item in inputs if item.get("name")}
                form_data[inp_name] = payload

                try:
                    if method == "POST":
                        resp = await client.post(action_url, data=form_data, headers=headers, timeout=self.timeout)
                    else:
                        resp = await client.get(action_url, params=form_data, headers=headers, timeout=self.timeout)

                    if self._is_reflected_unescaped(resp.text, pattern):
                        snippet = self._extract_evidence_snippet(resp.text, pattern)
                        vulnerabilities.append(Vulnerability(
                            id=f"XSS-FORM-{abs(hash(inp_name + action_url)) % 10000:04d}",
                            name=f"Reflected XSS in Form Field '{inp_name}'",
                            category="Cross-Site Scripting (XSS)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            description=f"Reflected XSS discovered in form field `{inp_name}` targeting `{action_url}`. Payload was echoed back in raw HTML.",
                            impact="Enables malicious JavaScript execution within the victim's session context.",
                            remediation="Sanitize and HTML-encode all form parameters before rendering output. Use secure modern frameworks that auto-escape variables.",
                            evidence=[FindingEvidence(
                                url=action_url,
                                parameter=inp_name,
                                payload=payload,
                                request_method=method,
                                response_status=resp.status_code,
                                response_snippet=snippet,
                                description=f"Form input reflection verified: {desc}"
                            )],
                            references=["https://owasp.org/www-community/attacks/xss/"]
                        ))
                        break
                except Exception:
                    continue

        return vulnerabilities
