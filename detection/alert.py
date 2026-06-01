"""
alert.py — Bir tespit kuralinin urettigi guvenlik alarmini temsil eden veri modeli.

Bagimlilik grafinde Seviye 0: hicbir proje modulunu import etmez. Tum tespit
kurallari (brute_force, enumeration, ...) sonuc olarak bu "Alert" nesnesini uretir.
Boylece CLI ve dashboard, alarmlarin nereden geldigini bilmeden hepsini ayni
sekilde gosterebilir.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Optional


class Severity(StrEnum):
    """
    Alarm onem derecesi.

    StrEnum sectik: JSON'a yazarken / template'te gosterirken dogrudan "high"
    string'i gibi davranir. Ama siralama (sorting) icin string yetmez — alfabetik
    siralama "high < low < medium" verir ki bu yanlis. Bu yuzden asagida sayisal
    bir 'rank' ekliyoruz.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """
        Siralama icin sayisal oncelik: high=2 > medium=1 > low=0.
        CLI alarmlari 'en yuksek once' gostermek icin bunu kullanir
        (sorted(..., key=lambda a: a.severity.rank, reverse=True)).
        """
        return {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}[self]


@dataclass
class Alert:
    """
    Tek bir guvenlik alarmi. Bir tespit kurali, esik degeri asildiginda bunu uretir.
    """

    rule_name: str                  # hangi kural uretti, orn "brute_force"
    severity: Severity              # low / medium / high
    source_ip: Optional[str]        # alarmin iliskili oldugu IP (yoksa None)
    count: int                      # kurali tetikleyen olay sayisi (orn 12 basarisiz deneme)
    time_window: Optional[str]      # insan-okur zaman penceresi, orn "05:50-05:53 (3 dk)"
    description: str                # alarmin tek cumlelik aciklamasi
    # evidence mutable bir liste; dataclass'ta mutable default DOGRUDAN yazilamaz
    # (tum nesneler ayni listeyi paylasirdi -> klasik Python tuzagi). Bu yuzden
    # default_factory=list ile her nesneye YENI bos liste veriyoruz.
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Alarmi JSON-uyumlu dict'e cevir (severity -> .value). Dashboard ve --json kullanir."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "count": self.count,
            "time_window": self.time_window,
            "description": self.description,
            "evidence": self.evidence,
        }
