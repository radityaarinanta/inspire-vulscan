import re
from typing import List, Dict, Any, Set
import httpx
from bs4 import BeautifulSoup
from ..models import TechItem

TECH_SIGNATURES = [
    # Web Servers & CDN
    {"name": "Cloudflare", "category": "CDN / WAF", "headers": {"server": r"cloudflare", "cf-ray": r".*"}},
    {"name": "Nginx", "category": "Web Server", "headers": {"server": r"nginx(?:/([\d\.]+))?"}},
    {"name": "Apache", "category": "Web Server", "headers": {"server": r"apache(?:/([\d\.]+))?"}},
    {"name": "Microsoft IIS", "category": "Web Server", "headers": {"server": r"microsoft-iis(?:/([\d\.]+))?"}},
    {"name": "Caddy", "category": "Web Server", "headers": {"server": r"caddy"}},
    {"name": "LiteSpeed", "category": "Web Server", "headers": {"server": r"litespeed"}},
    {"name": "Vercel", "category": "PaaS / Hosting", "headers": {"x-vercel-id": r".*"}},
    {"name": "Netlify", "category": "PaaS / Hosting", "headers": {"server": r"netlify"}},

    # Backend Frameworks / Languages
    {"name": "PHP", "category": "Programming Language", "headers": {"x-powered-by": r"php(?:/([\d\.]+))?"}, "cookies": [r"PHPSESSID"]},
    {"name": "Laravel", "category": "PHP Framework", "cookies": [r"laravel_session", r"XSRF-TOKEN"], "html": [r"laravel"]},
    {"name": "WordPress", "category": "CMS", "html": [r"/wp-content/", r"/wp-includes/", r'<meta name="generator" content="WordPress ([\d\.]+)"']},
    {"name": "Django", "category": "Python Framework", "cookies": [r"csrftoken", r"django"], "headers": {"set-cookie": r"csrftoken="}},
    {"name": "FastAPI", "category": "Python Framework", "html": [r"FastAPI", r"/docs", r"/redoc"]},
    {"name": "Flask", "category": "Python Framework", "cookies": [r"session"]},
    {"name": "ASP.NET", "category": "Web Framework", "headers": {"x-aspnet-version": r".*", "x-powered-by": r"ASP\.NET"}, "cookies": [r"ASP\.NET_SessionId"]},
    {"name": "Node.js / Express", "category": "Web Framework", "headers": {"x-powered-by": r"Express"}},
    {"name": "Next.js", "category": "React Framework", "headers": {"x-powered-by": r"Next\.js"}, "html": [r"/_next/static", r"__NEXT_DATA__"]},
    {"name": "Nuxt.js", "category": "Vue Framework", "html": [r"/_nuxt/", r"__NUXT__"]},

    # Frontend Libraries
    {"name": "React", "category": "Frontend Framework", "html": [r"data-reactroot", r"react\.production\.min\.js", r"/react-dom/"]},
    {"name": "Vue.js", "category": "Frontend Framework", "html": [r"data-v-[a-z0-9]+", r"vue\.js", r"vue\.runtime"]},
    {"name": "Angular", "category": "Frontend Framework", "html": [r"ng-version=", r"_ngcontent-", r"angular\.js"]},
    {"name": "jQuery", "category": "JavaScript Library", "html": [r"jquery(?:-([\d\.]+))?\.min\.js", r"jquery\.js"]},
    {"name": "Bootstrap", "category": "CSS Framework", "html": [r"bootstrap(?:-([\d\.]+))?\.min\.css", r"class=\".*col-(?:xs|sm|md|lg|xl)-"]},
    {"name": "Tailwind CSS", "category": "CSS Framework", "html": [r"tailwind", r"class=\".*(?:bg-opacity|backdrop-blur|flex-col|grid-cols-)"]}
]

class TechStackScanner:
    def __init__(self, target_url: str, timeout: float = 6.0, user_agent: str = ""):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agent = user_agent

    async def scan(self, client: httpx.AsyncClient) -> List[TechItem]:
        detected_map: Dict[str, TechItem] = {}
        headers_req = {"User-Agent": self.user_agent}

        try:
            resp = await client.get(self.target_url, headers=headers_req, timeout=self.timeout, follow_redirects=True)
            res_headers = {k.lower(): v for k, v in resp.headers.items()}
            html_text = resp.text
            cookies_header = resp.headers.get("set-cookie", "")

            for sig in TECH_SIGNATURES:
                name = sig["name"]
                category = sig["category"]
                version = None
                matched = False

                # 1. Match Headers
                if "headers" in sig:
                    for h_name, h_regex in sig["headers"].items():
                        if h_name in res_headers:
                            h_val = res_headers[h_name]
                            match = re.search(h_regex, h_val, re.IGNORECASE)
                            if match:
                                matched = True
                                if match.groups() and match.group(1):
                                    version = match.group(1)

                # 2. Match Cookies
                if not matched and "cookies" in sig:
                    for c_regex in sig["cookies"]:
                        if re.search(c_regex, cookies_header, re.IGNORECASE):
                            matched = True
                            break

                # 3. Match HTML content
                if not matched and "html" in sig:
                    for h_regex in sig["html"]:
                        match = re.search(h_regex, html_text, re.IGNORECASE)
                        if match:
                            matched = True
                            if match.groups() and match.group(1):
                                version = match.group(1)
                            break

                if matched:
                    detected_map[name] = TechItem(name=name, category=category, version=version)

        except Exception:
            pass

        return list(detected_map.values())
