"""
conftest.py — testler icin ortak yardimcilar.

Tespit kurallari Event nesneleri uzerinde calisir; bu yuzden burada log
metni parse etmeden DOGRUDAN Event uretebilen kucuk bir fabrika sunariz.
Boylece her test, zaman/IP/kullanici kombinasyonunu net ve deterministik
sekilde kurabilir (gercek saate veya ornek dosyaya bagimli kalmaz).
"""

from datetime import datetime, timedelta

import pytest

from parser.events import Event, EventType

# Tum testlerde sabit bir referans an. Gercek datetime.now()'a bagli kalmamak,
# testleri tekrarlanabilir kilar.
BASE = datetime(2026, 6, 1, 5, 0, 0)


def make_event(
    offset: float = 0.0,
    event_type: EventType = EventType.FAILED_PASSWORD,
    ip: str = "192.0.2.1",
    user: str = "root",
    host: str = "web-01",
    process: str = "sshd",
    port: int = 22000,
) -> Event:
    """
    BASE + offset saniyede tek bir Event uretir.

    raw_line, kanit (evidence) testlerinde gorunur olsun diye olay alanlarindan
    derlenir; gercek syslog formatina yakin ama parse edilmesi gerekmez.
    """
    ts = BASE + timedelta(seconds=offset)
    raw = (
        f"{ts.strftime('%b %e %H:%M:%S')} {host} {process}[1000]: "
        f"{event_type.value} user={user} ip={ip} port={port}"
    )
    return Event(
        timestamp=ts,
        host=host,
        process=process,
        event_type=event_type,
        username=user,
        source_ip=ip,
        port=port,
        raw_line=raw,
    )


def make_failures(n: int, ip: str = "192.0.2.1", step: float = 8.0, user: str = "root", start: float = 0.0):
    """Ayni IP'den 'step' saniye arayla n adet FAILED_PASSWORD olayi."""
    return [
        make_event(offset=start + i * step, event_type=EventType.FAILED_PASSWORD, ip=ip, user=user)
        for i in range(n)
    ]


@pytest.fixture
def ev():
    """Testlerde kisa kullanim icin fabrikayi fixture olarak da sun."""
    return make_event
