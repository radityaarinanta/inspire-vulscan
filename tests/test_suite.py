import os
import sys
import unittest
from datetime import datetime

# Ensure workspace root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import (
    ScanConfig, ScanResult, ScanSummary, Vulnerability, Severity,
    FindingEvidence, ScanProfile,
    MalwareScanResult, MalwareScanSummary, MalwareFinding,
    CategoryThreatStatus, MalwareThreatCategory
)
from core.reporter import ReportGenerator
from app import app
from fastapi.testclient import TestClient

class TestInspireCoreModels(unittest.TestCase):
    def test_vulnerability_model_creation(self):
        vuln = Vulnerability(
            id="SQLI-001",
            name="SQL Injection",
            severity=Severity.HIGH,
            category="Injection",
            description="Test SQLi injection vulnerability",
            impact="Potential data leakage",
            remediation="Use parameterized queries.",
            cvss_score=8.5,
            cwe_id="CWE-89",
            evidence=[FindingEvidence(request_method="GET", url="http://example.com?id=1", description="Parameter id vulnerable")]
        )
        self.assertEqual(vuln.severity, Severity.HIGH)
        self.assertEqual(vuln.cvss_score, 8.5)
        self.assertEqual(vuln.cwe_id, "CWE-89")

    def test_malware_finding_model_creation(self):
        finding = MalwareFinding(
            id="MAL-001",
            name="Coinhive Browser Miner",
            category=MalwareThreatCategory.CRYPTOJACKING,
            severity=Severity.CRITICAL,
            threat_score=95.0,
            description="In-browser miner detected",
            impact="High visitor CPU usage",
            remediation="Remove unauthorized script tag",
            evidence_snippet="CoinHive.Anonymous('key')",
            affected_url="http://example.com/miner.js"
        )
        self.assertEqual(finding.category, MalwareThreatCategory.CRYPTOJACKING)
        self.assertEqual(finding.threat_score, 95.0)

class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.reporter = ReportGenerator(reports_dir="reports")
        self.mock_result = ScanResult(
            scan_id="test-ci",
            target_url="http://example.local",
            start_time=datetime.utcnow().isoformat(),
            status="completed",
            config=ScanConfig(target_url="http://example.local", profile=ScanProfile.QUICK),
            summary=ScanSummary(total_vulnerabilities=1, high_severity=1, risk_score=15.0, security_grade="C"),
            vulnerabilities=[
                Vulnerability(
                    id="TEST-001",
                    name="Missing Content-Security-Policy",
                    severity=Severity.HIGH,
                    category="Security Headers",
                    description="Missing CSP header",
                    impact="XSS vulnerability",
                    remediation="Add CSP header",
                    cvss_score=6.5,
                    cwe_id="CWE-693",
                    evidence=[FindingEvidence(url="http://example.local", description="Header not present")]
                )
            ]
        )
        self.mock_malware_result = MalwareScanResult(
            scan_id="test-malware-ci",
            target_url="http://example.local",
            start_time=datetime.utcnow().isoformat(),
            status="completed",
            summary=MalwareScanSummary(is_clean=False, verdict="MALICIOUS THREATS DETECTED", overall_threat_score=90.0, total_threats=1),
            categories=[
                CategoryThreatStatus(category=MalwareThreatCategory.CRYPTOJACKING, is_infected=True, threat_count=1, details="Miner found")
            ],
            findings=[
                MalwareFinding(
                    id="MAL-001",
                    name="Coinhive Miner",
                    category=MalwareThreatCategory.CRYPTOJACKING,
                    severity=Severity.CRITICAL,
                    threat_score=90.0,
                    description="In-browser miner",
                    impact="High CPU",
                    remediation="Remove miner script",
                    affected_url="http://example.local/script.js"
                )
            ]
        )

    def test_json_report(self):
        path = self.reporter.generate_json_report(self.mock_result, "ci_test.json")
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove(path)

    def test_sarif_report(self):
        path = self.reporter.generate_sarif_report(self.mock_result, "ci_test.sarif")
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove(path)

    def test_csv_report(self):
        path = self.reporter.generate_csv_report(self.mock_result, "ci_test.csv")
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove(path)

    def test_html_report(self):
        path = self.reporter.generate_html_report(self.mock_result, "ci_test.html")
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove(path)

    def test_malware_reports(self):
        json_p = self.reporter.generate_malware_json_report(self.mock_malware_result, "ci_malware.json")
        csv_p = self.reporter.generate_malware_csv_report(self.mock_malware_result, "ci_malware.csv")
        html_p = self.reporter.generate_malware_html_report(self.mock_malware_result, "ci_malware.html")
        
        self.assertTrue(os.path.exists(json_p))
        self.assertTrue(os.path.exists(csv_p))
        self.assertTrue(os.path.exists(html_p))
        
        os.remove(json_p)
        os.remove(csv_p)
        os.remove(html_p)

class TestFastAPIServerEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_dashboard_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"INSPIRE", response.content)

    def test_demo_malware_sample_endpoint(self):
        response = self.client.get("/demo/malware-sample")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CoinHive", response.content)

if __name__ == "__main__":
    unittest.main(verbosity=2)
