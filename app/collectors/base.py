"""Common interface for all collectors (Wazuh, OPNsense, ...).

Each collector subclasses BaseCollector and implements collect().
A collector returns one result per check. The runner links each result to the
controls whose YAML entry has `automation: <name>:<check>`.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


@dataclass
class CheckResult:
    check: str             # e.g. agents_active (without the source prefix)
    status: str            # pass | fail | unknown
    summary: str
    raw: dict = field(default_factory=dict)


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """True when URL and credentials are set in .env."""

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Check connectivity to the source. Returns (ok, message)."""

    @abstractmethod
    def collect(self) -> list[CheckResult]:
        """Run all checks. A failing check becomes 'unknown' and never stops
        the remaining checks."""
