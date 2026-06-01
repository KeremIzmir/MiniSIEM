"""
events.py — Parse edilmis bir log olayini temsil eden veri modeli.

Bu dosya bagimlilik grafinin en altinda (Seviye 0): hicbir proje modulunu
import etmez, sadece stdlib kullanir. Boylece parser, detection, storage ve
dashboard katmanlarinin hepsi ayni "Event" tipini paylasabilir.
"""

from dataclasses import dataclass
from enum import StrEnum            # StrEnum: Python 3.11+ — uye hem str hem enum gibi davranir
from datetime import datetime
from typing import Optional


# Olay turleri. StrEnum sectik cunku JSON'a yazarken/dashboard'da gosterirken
# dogrudan string gibi davransin istiyoruz (event_type == "FAILED_PASSWORD" calisir).
class EventType(StrEnum):
    """auth.log icinden ayikladigimiz guvenlik olayi turleri."""

    FAILED_PASSWORD = "FAILED_PASSWORD"   # "Failed password for ... from IP" — hatali parola
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"     # "Accepted password/publickey ..." — basarili giris
    INVALID_USER = "INVALID_USER"         # "Invalid user X from IP" — var olmayan kullanici
    SUDO_FAILURE = "SUDO_FAILURE"         # sudo authentication failure
    AUTH_FAILURE = "AUTH_FAILURE"         # genel PAM authentication failure
    UNKNOWN = "UNKNOWN"                    # taninamayan ama olay olabilecek satir


@dataclass
class Event:
    """
    Tek bir parse edilmis log olayini tutar.

    dataclass kullanmak: __init__, __repr__, __eq__ gibi metodlari otomatik
    uretir; biz sadece alanlari tanimlariz. Tum tespit kurallari bu nesneler
    uzerinde calisir.
    """

    timestamp: datetime               # olayin zamani (auth.log'da yil yok -> parser ekler)
    host: str                         # olayin gerceklestigi sunucu adi (orn 'web-01')
    process: str                      # olayi ureten surec, orn 'sshd', 'sudo'
    event_type: EventType             # yukaridaki enum'dan olay turu
    username: Optional[str]           # ilgili kullanici adi (yoksa None)
    source_ip: Optional[str]          # baglantinin geldigi IP (yoksa None)
    port: Optional[int]               # kaynak port (yoksa None)
    raw_line: str                     # orijinal ham log satiri (kanit/evidence icin saklanir)

    def to_dict(self) -> dict:
        """
        Event'i JSON-uyumlu bir dict'e cevirir.

        datetime ve EventType dogrudan json.dumps ile serialize edilemez,
        bu yuzden timestamp -> ISO string, event_type -> .value yapariz.
        Storage (JSON dosyasi) ve dashboard (Flask jsonify) bunu kullanir.
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "process": self.process,
            "event_type": self.event_type.value,
            "username": self.username,
            "source_ip": self.source_ip,
            "port": self.port,
            "raw_line": self.raw_line,
        }

    @property
    def is_failure(self) -> bool:
        """Bu olay bir kimlik dogrulama BASARISIZLIGI mi? (tespit kurallari bunu sayar)"""
        return self.event_type in (
            EventType.FAILED_PASSWORD,
            EventType.INVALID_USER,
            EventType.SUDO_FAILURE,
            EventType.AUTH_FAILURE,
        )

    @property
    def is_success(self) -> bool:
        """Bu olay BASARILI bir giris mi? ('basarisiz sonra basarili' kalibi icin onemli)"""
        return self.event_type == EventType.ACCEPTED_LOGIN
