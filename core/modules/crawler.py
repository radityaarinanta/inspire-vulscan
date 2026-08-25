import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Any
import httpx
from bs4 import BeautifulSoup

class DiscoveredForm:
    def __init__(self, action_url: str, method: str, inputs: List[Dict[str, str]]):
        self.action_url = action_url
        self.method = method.upper()
        self.inputs = inputs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_url": self.action_url,
            "method": self.method,
            "inputs": self.inputs
        }

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 15, timeout: float = 8.0, user_agent: str = ""):
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme or "http"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent
        self.visited_urls: Set[str] = set()
        self.discovered_forms: List[DiscoveredForm] = []
        self.urls_with_params: List[str] = []

    def _is_same_domain(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        return netloc == self.domain or not netloc

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    async def crawl(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        queue = [(self.base_url, 0)]
        self.visited_urls.add(self.base_url)
        
        while queue and len(self.visited_urls) <= self.max_pages:
            current_url, depth = queue.pop(0)
            
            # Record if URL contains query parameters
            if "?" in current_url and current_url not in self.urls_with_params:
                self.urls_with_params.append(current_url)

            if depth > self.max_depth:
                continue

            try:
                headers = {"User-Agent": self.user_agent}
                resp = await client.get(current_url, headers=headers, timeout=self.timeout, follow_redirects=True)
                content_type = resp.headers.get("content-type", "").lower()
                
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract forms
                for form in soup.find_all("form"):
                    action = form.get("action") or current_url
                    action_url = urljoin(current_url, action)
                    method = form.get("method", "GET")
                    inputs = []
                    
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({
                                "name": name,
                                "type": inp.get("type", "text"),
                                "value": inp.get("value", "")
                            })
                    
                    if inputs:
                        self.discovered_forms.append(DiscoveredForm(action_url, method, inputs))

                # Extract links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href.startswith(("mailto:", "javascript:", "tel:", "#")):
                        continue

                    full_url = urljoin(current_url, href)
                    norm_url = self._normalize_url(full_url)

                    if self._is_same_domain(norm_url) and norm_url not in self.visited_urls:
                        if len(self.visited_urls) < self.max_pages:
                            self.visited_urls.add(norm_url)
                            queue.append((norm_url, depth + 1))

            except Exception:
                pass

        return {
            "visited_urls": list(self.visited_urls),
            "urls_with_params": self.urls_with_params,
            "discovered_forms": [f.to_dict() for f in self.discovered_forms]
        }
