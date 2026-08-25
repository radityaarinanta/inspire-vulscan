"""
Inspire Security Suite Vulnerability & Audit Modules
"""
from .crawler import WebCrawler
from .headers import SecurityHeadersScanner
from .sqli import SQLInjectionScanner
from .xss import XSSScanner
from .sensitive_files import SensitiveFilesScanner
from .open_redirect import OpenRedirectScanner
from .ssl_tls import SSLScanner
from .tech_stack import TechStackScanner

__all__ = [
    "WebCrawler",
    "SecurityHeadersScanner",
    "SQLInjectionScanner",
    "XSSScanner",
    "SensitiveFilesScanner",
    "OpenRedirectScanner",
    "SSLScanner",
    "TechStackScanner"
]
