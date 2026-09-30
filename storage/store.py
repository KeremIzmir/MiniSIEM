"""
store.py — Olaylari ve alarmlari tutan basit depo (in-memory + JSON).

Bagimlilik: parser/events.py (Event). Alert'i de saklariz ama Alert.to_dict()
zaten dict verdigi icin tipi import etmeden 'Any' gibi davranabiliriz; yine de
okunabilirlik icin tip ipucu olarak 'object' kullaniyoruz.

NEDEN BOYLE: Once en basit calisan seyi istiyoruz (bellek + JSON dump). Ama
ileride SQLite'a gecis kolay olsun diye TUM erisim bu sinif arkasinda. Yani
dashboard/CLI dogrudan listeye degil, EventStore metodlarina konusur. Yarin
add_event() icine 'INSERT INTO events ...' yazsak disaridaki kod degismez.
"""

import json
from collections import Counter
from typing import Optional

from parser.events import Event


class EventStore:
    """Olaylari ve uretilen alarmlari bellekte tutar; JSON'a yazip okuyabilir."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._alerts: list[dict] = []   # alarmlari to_dict() formatinda tutariz (depo sunumdan bagimsiz)
        self.unparsed_count: int = 0    # parser'in cozemedigi satir sayisi (raporlanir)

    # ----------------------------- yazma ----------------------------------- #
    def add_event(self, event: Event) -> None:
        """Tek bir olayi ekle. (SQLite'a gecince burasi tek degisecek yer olur.)"""
        self._events.append(event)

    def add_events(self, events: list[Event]) -> None:
        """Toplu olay ekle."""
        self._events.extend(events)

    def add_alert(self, alert: object) -> None:
        """
        Bir Alert ekle. Alert nesnesinin to_dict() metodu varsa onu kullaniriz;
        boylece storage, detection.alert modulune dogrudan bagimli olmaz (gevsek baglilik).
        """
        if hasattr(alert, "to_dict"):
            self._alerts.append(alert.to_dict())
        else:
            self._alerts.append(dict(alert))  # zaten dict ise

    # ----------------------------- okuma ----------------------------------- #
    @property
    def events(self) -> list[Event]:
        return self._events

    @property
    def alerts(self) -> list[dict]:
        return self._alerts

    def failed_events(self) -> list[Event]:
        """Sadece basarisiz kimlik dogrulama olaylari (Event.is_failure)."""
        return [e for e in self._events if e.is_failure]

    def unique_ips(self) -> set[str]:
        """Olaylarda gecen benzersiz kaynak IP kumesi (None'lari atla)."""
        return {e.source_ip for e in self._events if e.source_ip}

    def top_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        """
        En cok olay ureten IP'ler: [(ip, sayi), ...] azalan sirada.
        Dashboard'daki 'en cok deneme yapan IP'ler' tablosunu besler.
        """
        counter = Counter(e.source_ip for e in self._events if e.source_ip)
        return counter.most_common(limit)

    def failed_per_minute(self) -> list[tuple[str, int]]:
        """
        Dakika bazinda basarisiz kimlik dogrulama sayisi: [("2026-06-01 05:50", 8), ...] zaman sirali.
        Dashboard'daki zaman serisi grafigi bunu kullanir.
        """
        counter: Counter = Counter()
        for e in self.failed_events():
            bucket = e.timestamp.strftime("%Y-%m-%d %H:%M")  # saniyeyi at -> dakikaya yuvarla
            counter[bucket] += 1
        return sorted(counter.items())  # zamana gore sirala

    def summary(self) -> dict:
        """
        CLI ozet tablosu + dashboard ust kartlari icin tek bakista sayilar.

        basarisiz_kimlik_dogrulama: kanonik alan; Event.is_failure olaylarini sayar.
        basarisiz_giris: geriye uyumluluk icin korunan DEPRECATED alias. Ayni hesaplamadan
        gelir, bu yuzden iki deger her zaman esittir.
        """
        failures = len(self.failed_events())
        return {
            "toplam_olay": len(self._events),
            "basarisiz_kimlik_dogrulama": failures,
            "basarisiz_giris": failures,  # deprecated alias: mevcut tuketiciler kirilmasin
            "benzersiz_ip": len(self.unique_ips()),
            "alarm_sayisi": len(self._alerts),
            "unparsed": self.unparsed_count,
        }

    # --------------------------- kalicilik (JSON) -------------------------- #
    def to_json(self, path: Optional[str] = None) -> str:
        """
        Tum depoyu JSON string'e cevirir. path verilirse dosyaya da yazar.
        ensure_ascii=False: Turkce karakterler okunur kalsin. indent=2: insan-okur.
        """
        payload = {
            "summary": self.summary(),
            "events": [e.to_dict() for e in self._events],
            "alerts": self._alerts,
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return text
