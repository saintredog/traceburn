"""
src/scanner — Discovery module

Exports the public API for all scanner sub-components.
"""

from src.scanner.broker_scraper import BrokerScraper, ScrapeResult, SpokeoScraper
from src.scanner.dork_scanner import DorkResult, DorkScanner
from src.scanner.engine import ScannerEngine, ScanSummary
from src.scanner.hibp_client import BreachRecord, HIBPClient
from src.scanner.pii_matcher import MatchResult, PIIMatcher

__all__ = [
    "BrokerScraper",
    "BreachRecord",
    "DorkResult",
    "DorkScanner",
    "HIBPClient",
    "MatchResult",
    "PIIMatcher",
    "ScannerEngine",
    "ScanSummary",
    "ScrapeResult",
    "SpokeoScraper",
]
