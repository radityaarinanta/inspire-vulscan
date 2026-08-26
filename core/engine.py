import asyncio
import time
import uuid
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
import httpx

from .models import (
    ScanConfig, ScanResult, ScanSummary, ScanProgress,
    Vulnerability, Severity, ScanProfile, SSLInfo, TechItem,
    MalwareScanResult, MalwareScanSummary, CategoryThreatStatus, MalwareThreatCategory
)
from .modules.crawler import WebCrawler
from .modules.headers import SecurityHeadersScanner
from .modules.sqli import SQLInjectionScanner
from .modules.xss import XSSScanner
from .modules.sensitive_files import SensitiveFilesScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.ssl_tls import SSLScanner
from .modules.tech_stack import TechStackScanner

class ScanEngine:
    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_progress: Dict[str, ScanProgress] = {}
        self.subscribers: Dict[str, List[Callable[[Dict[str, Any]], Any]]] = {}

    def subscribe(self, scan_id: str, callback: Callable[[Dict[str, Any]], Any]):
        if scan_id not in self.subscribers:
            self.subscribers[scan_id] = []
        self.subscribers[scan_id].append(callback)

    def unsubscribe(self, scan_id: str, callback: Callable[[Dict[str, Any]], Any]):
        if scan_id in self.subscribers and callback in self.subscribers[scan_id]:
            self.subscribers[scan_id].remove(callback)

    async def _notify(self, scan_id: str, event_type: str, data: Dict[str, Any]):
        message = {"event": event_type, "scan_id": scan_id, "data": data, "timestamp": datetime.utcnow().isoformat()}
        if scan_id in self.subscribers:
            for callback in list(self.subscribers[scan_id]):
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(message)
                    else:
                        callback(message)
                except Exception:
                    pass

    def _calculate_score_and_grade(self, vulnerabilities: List[Vulnerability]) -> tuple[float, str]:
        if not vulnerabilities:
            return 0.0, "A+"

        # Deductions
        crit_count = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        med_count = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low_count = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)
        info_count = sum(1 for v in vulnerabilities if v.severity == Severity.INFO)

        risk_score = (crit_count * 30.0) + (high_count * 15.0) + (med_count * 5.0) + (low_count * 1.5) + (info_count * 0.5)
        risk_score = min(100.0, risk_score)

        # Grade calculation
        if crit_count >= 2 or risk_score >= 80:
            grade = "F"
        elif crit_count == 1 or risk_score >= 60:
            grade = "D"
        elif high_count >= 2 or risk_score >= 40:
            grade = "C"
        elif high_count == 1 or med_count >= 3 or risk_score >= 20:
            grade = "B"
        elif med_count >= 1 or low_count >= 3 or risk_score > 5:
            grade = "A"
        else:
            grade = "A+"

        return round(risk_score, 1), grade

    async def run_scan(self, config: ScanConfig, scan_id: Optional[str] = None) -> ScanResult:
        scan_id = scan_id or str(uuid.uuid4())[:8]
        start_time_str = datetime.utcnow().isoformat()
        start_ts = time.time()

        # Initialize tracking
        progress = ScanProgress(
            scan_id=scan_id,
            target_url=config.target_url,
            status="initializing",
            progress_percentage=5,
            current_action="Initializing security test modules...",
            logs=[f"[{datetime.now().strftime('%H:%M:%S')}] Initializing Inspire Security Suite engine for {config.target_url}"]
        )
        self.scan_progress[scan_id] = progress

        result = ScanResult(
            scan_id=scan_id,
            target_url=config.target_url,
            start_time=start_time_str,
            status="running",
            config=config,
            summary=ScanSummary(),
            technologies=[],
            vulnerabilities=[],
            crawled_urls=[]
        )
        self.active_scans[scan_id] = result

        await self._notify(scan_id, "progress", progress.model_dump())

        # Async HTTP client with connection pool
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        async with httpx.AsyncClient(verify=False, limits=limits, timeout=config.timeout) as client:
            all_vulnerabilities: List[Vulnerability] = []

            # Step 1: Passive Recon & Infrastructure (Tech Stack, SSL, Headers)
            progress.status = "recon"
            progress.progress_percentage = 15
            progress.current_action = "Analyzing SSL/TLS certificate & Infrastructure..."
            progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Running SSL/TLS certificate inspection and tech stack identification...")
            await self._notify(scan_id, "progress", progress.model_dump())

            # SSL Check
            if config.check_ssl:
                ssl_scanner = SSLScanner(config.target_url, timeout=config.timeout)
                ssl_info, ssl_vulns = await ssl_scanner.scan()
                result.ssl_info = ssl_info
                all_vulnerabilities.extend(ssl_vulns)
                for v in ssl_vulns:
                    progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [!] {v.severity.value} finding: {v.name}")

            # Tech Stack Check
            if config.check_tech_stack:
                tech_scanner = TechStackScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)
                tech_items = await tech_scanner.scan(client)
                result.technologies = tech_items
                if tech_items:
                    tech_names = ", ".join([f"{t.name} ({t.category})" for t in tech_items[:4]])
                    progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Detected Technologies: {tech_names}")

            # Security Headers Check
            if config.check_headers:
                progress.progress_percentage = 30
                progress.current_action = "Auditing Security Headers, CORS, and Cookie flags..."
                progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Auditing HTTP Response Headers and Cookie Security Attributes...")
                await self._notify(scan_id, "progress", progress.model_dump())
                
                header_scanner = SecurityHeadersScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)
                hdr_vulns = await header_scanner.scan(client)
                all_vulnerabilities.extend(hdr_vulns)
                progress.findings_count = len(all_vulnerabilities)

            # Step 2: Sensitive Directory / File Discovery
            if config.check_sensitive_files:
                progress.progress_percentage = 45
                progress.current_action = "Probing for exposed sensitive files & endpoints..."
                progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Testing for exposed configuration (.env, .git, backups, admin panels)...")
                await self._notify(scan_id, "progress", progress.model_dump())

                sens_scanner = SensitiveFilesScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)
                sens_vulns = await sens_scanner.scan(client)
                all_vulnerabilities.extend(sens_vulns)
                progress.findings_count = len(all_vulnerabilities)

            # Step 3: Web Crawler (if Profile is Standard or Deep)
            crawled_urls = [config.target_url]
            discovered_forms = []
            if config.profile in [ScanProfile.STANDARD, ScanProfile.DEEP]:
                progress.progress_percentage = 60
                progress.current_action = "Crawling website structure & discovering input endpoints..."
                progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Crawling target web application (depth: {config.max_crawl_depth}, max pages: {config.max_pages})...")
                await self._notify(scan_id, "progress", progress.model_dump())

                crawler = WebCrawler(
                    config.target_url,
                    max_depth=config.max_crawl_depth,
                    max_pages=config.max_pages,
                    timeout=config.timeout,
                    user_agent=config.user_agent
                )
                crawl_result = await crawler.crawl(client)
                crawled_urls = crawl_result["visited_urls"] or [config.target_url]
                discovered_forms = crawl_result["discovered_forms"]
                result.crawled_urls = crawled_urls
                progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Crawling complete: {len(crawled_urls)} pages mapped, {len(discovered_forms)} HTML forms discovered.")

            # Step 4: Active Vulnerability Scans (SQLi, XSS, Open Redirect)
            progress.progress_percentage = 75
            progress.current_action = "Running active vulnerability injections (SQLi, XSS, Redirects)..."
            progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Launching active penetration modules against mapped parameters and forms...")
            await self._notify(scan_id, "progress", progress.model_dump())

            sqli_scanner = SQLInjectionScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)
            xss_scanner = XSSScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)
            redirect_scanner = OpenRedirectScanner(config.target_url, timeout=config.timeout, user_agent=config.user_agent)

            # Test URL parameters
            for page_url in crawled_urls:
                if config.check_sqli:
                    sqli_vulns = await sqli_scanner.scan_url_params(page_url, client)
                    all_vulnerabilities.extend(sqli_vulns)
                if config.check_xss:
                    xss_vulns = await xss_scanner.scan_url_params(page_url, client)
                    all_vulnerabilities.extend(xss_vulns)
                if config.check_open_redirect:
                    redir_vulns = await redirect_scanner.scan_url(page_url, client)
                    all_vulnerabilities.extend(redir_vulns)

            # Test Forms
            for form in discovered_forms:
                if config.check_sqli:
                    form_sqli = await sqli_scanner.scan_form(form, client)
                    all_vulnerabilities.extend(form_sqli)
                if config.check_xss:
                    form_xss = await xss_scanner.scan_form(form, client)
                    all_vulnerabilities.extend(form_xss)

            progress.findings_count = len(all_vulnerabilities)

            # Step 5: Final Analysis & Summary Calculation
            progress.progress_percentage = 95
            progress.current_action = "Calculating risk metrics & security rating..."
            progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Synthesizing findings and calculating OWASP/CVSS risk score...")
            await self._notify(scan_id, "progress", progress.model_dump())

            duration = round(time.time() - start_ts, 2)
            risk_score, grade = self._calculate_score_and_grade(all_vulnerabilities)

            summary = ScanSummary(
                total_findings=len(all_vulnerabilities),
                critical_count=sum(1 for v in all_vulnerabilities if v.severity == Severity.CRITICAL),
                high_count=sum(1 for v in all_vulnerabilities if v.severity == Severity.HIGH),
                medium_count=sum(1 for v in all_vulnerabilities if v.severity == Severity.MEDIUM),
                low_count=sum(1 for v in all_vulnerabilities if v.severity == Severity.LOW),
                info_count=sum(1 for v in all_vulnerabilities if v.severity == Severity.INFO),
                security_grade=grade,
                risk_score=risk_score,
                urls_crawled_count=len(crawled_urls),
                duration_seconds=duration
            )

            result.summary = summary
            result.vulnerabilities = all_vulnerabilities
            result.end_time = datetime.utcnow().isoformat()
            result.status = "completed"

            progress.status = "completed"
            progress.progress_percentage = 100
            progress.current_action = f"Scan completed in {duration}s. Grade: {grade}, Score: {risk_score}/100"
            progress.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [✓] Scan complete! Total findings: {len(all_vulnerabilities)} | Security Grade: {grade}")
            
            await self._notify(scan_id, "completed", result.model_dump())
            await self._notify(scan_id, "progress", progress.model_dump())

        return result

    async def run_malware_scan(self, target_url: str, scan_id: Optional[str] = None) -> MalwareScanResult:
        scan_id = scan_id or str(uuid.uuid4())[:8]
        start_time = datetime.utcnow().isoformat()
        t0 = time.time()

        from .models import MalwareScanResult, MalwareScanSummary, CategoryThreatStatus, MalwareThreatCategory
        from .modules.malware import WebMalwareScanner

        scanner = WebMalwareScanner(target_url=target_url)

        async with httpx.AsyncClient(verify=False) as client:
            findings, metrics = await scanner.scan(client)

        duration = round(time.time() - t0, 2)
        total_threats = len(findings)
        critical_threats = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_threats = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_threats = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        # Compute overall threat score
        if findings:
            max_threat_score = max(f.threat_score for f in findings)
            overall_threat_score = round(min(100.0, max_threat_score + (total_threats - 1) * 2.0), 1)
        else:
            overall_threat_score = 0.0

        if overall_threat_score >= 80.0 or critical_threats > 0:
            verdict = "MALICIOUS THREATS DETECTED"
            is_clean = False
        elif overall_threat_score > 0.0:
            verdict = "SUSPICIOUS ACTIVITY DETECTED"
            is_clean = False
        else:
            verdict = "SITE CLEAN"
            is_clean = True

        # Category status breakdown
        category_statuses = []
        for cat in [
            MalwareThreatCategory.CRYPTOJACKING,
            MalwareThreatCategory.CARD_SKIMMER,
            MalwareThreatCategory.OBFUSCATED_SCRIPT,
            MalwareThreatCategory.STEALTH_IFRAME,
            MalwareThreatCategory.EXPOSED_BACKDOOR,
            MalwareThreatCategory.DEFACEMENT_SPAM
        ]:
            cat_findings = [f for f in findings if f.category == cat]
            is_inf = len(cat_findings) > 0
            category_statuses.append(CategoryThreatStatus(
                category=cat,
                is_infected=is_inf,
                count=len(cat_findings),
                details=f"{len(cat_findings)} threat(s) detected" if is_inf else "Clean"
            ))

        summary = MalwareScanSummary(
            is_clean=is_clean,
            verdict=verdict,
            overall_threat_score=overall_threat_score,
            total_threats=total_threats,
            critical_threats=critical_threats,
            high_threats=high_threats,
            medium_threats=medium_threats,
            scripts_analyzed=metrics.get("scripts_analyzed", 0),
            iframes_analyzed=metrics.get("iframes_analyzed", 0),
            backdoors_probed=metrics.get("backdoors_probed", 0),
            duration_seconds=duration
        )

        malware_result = MalwareScanResult(
            scan_id=scan_id,
            target_url=target_url,
            start_time=start_time,
            end_time=datetime.utcnow().isoformat(),
            status="completed",
            summary=summary,
            categories=category_statuses,
            findings=findings
        )

        if not hasattr(self, "active_malware_scans"):
            self.active_malware_scans = {}
        self.active_malware_scans[scan_id] = malware_result

        return malware_result

# Global Engine Singleton
scanner_engine = ScanEngine()
scanner_engine.active_malware_scans = {}

