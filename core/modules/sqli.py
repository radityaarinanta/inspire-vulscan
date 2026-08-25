import re
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Vulnerability, Severity, FindingEvidence

SQL_ERRORS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"check the manual that corresponds to your (mysql|mariadb) server version",
        r"mySqlClient\.",
        r"com\.mysql\.jdbc"
    ],
    "PostgreSQL": [
        r"postgresql.*error",
        r"warning:\s+pg_",
        r"syntax error at or near",
        r"org\.postgresql\.util\.PSQLException"
    ],
    "Microsoft SQL Server": [
        r"driver.* sql[\-\_\ ]*server",
        r"ole db.* sql server",
        r"unclosed quotation mark after the character string",
        r"syntax error.*in query expression",
        r"com\.microsoft\.sqlserver\.jdbc"
    ],
    "Oracle": [
        r"ora-[0-9]{4,5}",
        r"oracle error",
        r"oracle.*driver"
    ],
    "SQLite": [
        r"sqlite3::sqlexception",
        r"sqlite_error",
        r"sqlite exception",
        r"unrecognized token:",
        r"near \".*\": syntax error"
    ]
}

SQLI_PAYLOADS = [
    ("'", "Single quote syntax break"),
    ("''", "Escaped single quote"),
    ("\"", "Double quote syntax break"),
    ("' OR '1'='1", "Boolean-based always-true"),
    ("' OR '1'='2", "Boolean-based always-false"),
    ("1' ORDER BY 1--", "Order by column discovery"),
    ("1' UNION SELECT NULL--", "Union-based injection attempt"),
    ("1' AND SLEEP(0)--", "Time-based benign probe")
]

class SQLInjectionScanner:
    def __init__(self, target_url: str, timeout: float = 8.0, user_agent: str = ""):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent

    def _check_db_error(self, response_text: str) -> Tuple[bool, str, str]:
        for db_name, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    # Extract surrounding context
                    start = max(0, match.start() - 30)
                    end = min(len(response_text), match.end() + 50)
                    snippet = html.escape(response_text[start:end].strip())
                    return True, db_name, snippet
        return False, "", ""

    async def scan_url_params(self, url: str, client: httpx.AsyncClient) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulnerabilities

        headers = {"User-Agent": self.user_agent}

        # Baseline request
        try:
            base_resp = await client.get(url, headers=headers, timeout=self.timeout)
            base_text = base_resp.text
        except Exception:
            return vulnerabilities

        for param_name, param_values in params.items():
            original_val = param_values[0] if param_values else ""
            
            for payload, desc in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [original_val + payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                try:
                    resp = await client.get(test_url, headers=headers, timeout=self.timeout)
                    has_error, db_name, snippet = self._check_db_error(resp.text)

                    if has_error:
                        vulnerabilities.append(Vulnerability(
                            id=f"SQLI-{abs(hash(param_name + url)) % 10000:04d}",
                            name=f"SQL Injection in Parameter '{param_name}' ({db_name})",
                            category="Injection",
                            severity=Severity.CRITICAL,
                            cvss_score=9.3,
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            description=f"A database error indicating SQL Injection vulnerability was triggered when injecting payload `{payload}` into parameter `{param_name}`. Detected Database: {db_name}.",
                            impact="Attackers can bypass authentication, extract confidential database records, alter data, or potentially achieve Remote Code Execution (RCE).",
                            remediation="Use Parameterized Queries / Prepared Statements (e.g. PDO, SQLAlchemy, Prisma) or Stored Procedures. Never concatenate user input directly into SQL queries.",
                            evidence=[FindingEvidence(
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                request_method="GET",
                                response_status=resp.status_code,
                                response_snippet=snippet,
                                description=f"Database error matched: {desc}"
                            )],
                            references=["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                        ))
                        break  # Found high-confidence vuln on this param, proceed to next
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

            for payload, desc in SQLI_PAYLOADS[:4]:  # test top payloads on forms
                form_data = {item.get("name"): item.get("value", "") for item in inputs if item.get("name")}
                form_data[inp_name] = (form_data.get(inp_name, "") or "test") + payload

                try:
                    if method == "POST":
                        resp = await client.post(action_url, data=form_data, headers=headers, timeout=self.timeout)
                    else:
                        resp = await client.get(action_url, params=form_data, headers=headers, timeout=self.timeout)

                    has_error, db_name, snippet = self._check_db_error(resp.text)
                    if has_error:
                        vulnerabilities.append(Vulnerability(
                            id=f"SQLI-FORM-{abs(hash(inp_name + action_url)) % 10000:04d}",
                            name=f"SQL Injection in Form Input '{inp_name}' ({db_name})",
                            category="Injection",
                            severity=Severity.CRITICAL,
                            cvss_score=9.3,
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            description=f"A database error occurred in form submission at `{action_url}` with input `{inp_name}` when tested with payload `{payload}`.",
                            impact="Unauthorized database disclosure, credential theft, data tampering, or full backend compromise.",
                            remediation="Implement Parameterized Statements (Prepared Queries) and robust input validation on all form handlers.",
                            evidence=[FindingEvidence(
                                url=action_url,
                                parameter=inp_name,
                                payload=payload,
                                request_method=method,
                                response_status=resp.status_code,
                                response_snippet=snippet,
                                description=f"Form SQL injection matched: {desc}"
                            )],
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                        ))
                        break
                except Exception:
                    continue

        return vulnerabilities
