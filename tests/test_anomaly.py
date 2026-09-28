"""
test_anomaly.py — z-score tabanli hacim anomalisi + is_public_ip yardimcisi.

Kenar durumlar:
  - is_public_ip: public / private / gecersiz
  - en az 2 IP yoksa istatistik yapilamaz -> bos
  - tek bir IP hacimce belirgin aykirisa -> alarm
  - min_volume freni: z yuksek ama mutlak hacim kucukse -> alarm YOK
  - tum hacimler esitse (stdev=0) -> alarm YOK
"""

from parser.events import EventType
from detection.anomaly import detect_anomalous_ips, is_public_ip
from conftest import make_event


def _events_for(volume_by_ip: dict) -> list:
    """{ip: adet} -> her IP icin o kadar FAILED_PASSWORD olayi."""
    events = []
    offset = 0
    for ip, vol in volume_by_ip.items():
        for _ in range(vol):
            events.append(make_event(offset=offset, event_type=EventType.FAILED_PASSWORD, ip=ip))
            offset += 1
    return events


def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("not-an-ip") is False   # gecersiz -> sessizce False


def test_needs_at_least_two_ips():
    events = _events_for({"192.0.2.1": 50})
    assert detect_anomalous_ips(events) == []


def test_clear_outlier_triggers():
    # Bir IP 20 olay, digerleri 1'er -> belirgin aykiri.
    events = _events_for({"192.0.2.1": 20, "192.0.2.2": 1, "192.0.2.3": 1,
                          "192.0.2.4": 1, "192.0.2.5": 1, "192.0.2.6": 1})
    alerts = detect_anomalous_ips(events, k=2.0, min_volume=5)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "anomalous_ip"
    assert a.source_ip == "192.0.2.1"
    assert a.count == 20


def test_min_volume_brake():
    # A=4 istatistiksel olarak aykiri olsa da min_volume=5 altinda -> alarm yok.
    events = _events_for({"192.0.2.1": 4, "192.0.2.2": 1, "192.0.2.3": 1, "192.0.2.4": 1,
                          "192.0.2.5": 1, "192.0.2.6": 1, "192.0.2.7": 1})
    assert detect_anomalous_ips(events, k=2.0, min_volume=5) == []


def test_uniform_volumes_no_alert():
    # Tum IP'ler esit hacim -> stdev=0 -> aykiri yok.
    events = _events_for({"192.0.2.1": 5, "192.0.2.2": 5, "192.0.2.3": 5})
    assert detect_anomalous_ips(events) == []


# --------------------------------------------------------------------------- #
# MASKELEME (masking) — aykiri deger kendi esigini sisirmemeli
# --------------------------------------------------------------------------- #
def test_small_sample_outlier_is_detected():
    """
    ESKI HATA: esik, aykiri degerin KENDISI dahil hesaplaniyordu. Anakitle
    sapmasiyla n elemanda max z-score sqrt(n-1) oldugu icin k=2.0'da n<6 iken
    alarm MATEMATIKSEL OLARAK imkansizdi — 100 kat aykiri bile kaciyordu.
    Leave-one-out ile taban 'digerleri'nden hesaplanir.
    """
    for n in (3, 4, 5):
        vols = {"192.0.2.1": 100}
        vols.update({f"192.0.2.{i}": 1 for i in range(2, n + 1)})
        alerts = detect_anomalous_ips(_events_for(vols), k=2.0, min_volume=5)
        assert len(alerts) == 1, f"n={n} icin aykiri deger yakalanmadi"
        assert alerts[0].source_ip == "192.0.2.1"
        assert alerts[0].count == 100


def test_needs_at_least_three_ips():
    """Leave-one-out icin aday disarida kalinca tabanda en az 2 IP kalmali."""
    assert detect_anomalous_ips(_events_for({"192.0.2.1": 50, "192.0.2.2": 1})) == []


def test_mild_variation_does_not_alert():
    """Hafif dalgalanma aykiri degildir; kural gurultu uretmemeli."""
    vols = {"192.0.2.1": 6}
    vols.update({f"192.0.2.{i}": 5 for i in range(2, 7)})
    assert detect_anomalous_ips(_events_for(vols), k=2.0, min_volume=5) == []


def test_stdev_floor_prevents_alert_on_identical_baseline():
    """
    Taban tamamen esitse sapma 0'dir; sapma tabani (floor) olmasaydi 1 olay
    fazlasi bile 'aykiri' sayilirdi.
    """
    vols = {"192.0.2.1": 6, "192.0.2.2": 5, "192.0.2.3": 5, "192.0.2.4": 5}
    assert detect_anomalous_ips(_events_for(vols), k=2.0, min_volume=5) == []


def test_severity_high_when_failure_ratio_high():
    vols = {"192.0.2.1": 40}
    vols.update({f"192.0.2.{i}": 1 for i in range(2, 6)})
    alert = detect_anomalous_ips(_events_for(vols), k=2.0, min_volume=5)[0]
    # _events_for yalnizca FAILED_PASSWORD uretir -> oran %100 -> HIGH.
    assert alert.severity.value == "high"
    # Aciklama, esigin ADAY HARIC hesaplandigini acikca soylemeli.
    assert "diger IP ortalamasi" in alert.description
