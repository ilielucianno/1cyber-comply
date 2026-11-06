"""Interfata comuna pentru toti colectorii (Wazuh, OPNsense, ...).

Fiecare colector nou mosteneste BaseCollector si implementeaza collect().
Asa adaugam surse noi fara sa modificam restul aplicatiei.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class EvidenceItem:
    control_id: str
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
    def collect(self) -> list[EvidenceItem]:
        """Colecteaza dovezile si le mapeaza pe controale."""
