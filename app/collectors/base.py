"""Interfata comuna pentru toti colectorii (Wazuh, OPNsense, ...).

Fiecare colector nou mosteneste BaseCollector si implementeaza collect().
Un colector produce rezultate per verificare ("check"). Runner-ul le leaga de
controalele care au in YAML `automation: <name>:<check>`.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


@dataclass
class CheckResult:
    check: str             # ex: agents_active (fara prefixul sursei)
    status: str            # pass | fail | unknown
    summary: str
    raw: dict = field(default_factory=dict)


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """True daca exista URL/credentiale in .env."""

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Verifica legatura cu sursa. Returneaza (ok, mesaj)."""

    @abstractmethod
    def collect(self) -> list[CheckResult]:
        """Ruleaza toate verificarile. O verificare care esueaza devine 'unknown',
        nu opreste celelalte verificari."""
