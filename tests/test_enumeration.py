"""
test_enumeration.py — kullanici-enumeration (cesitlilik) tespiti.

Cekirdek fikir: SAYIM degil CESITLILIK. Ayni IP'den COK FARKLI kullanici adi
denenmesi alarm uretir; ayni kullanicinin 100 kez denenmesi uretmez (o brute-force).
"""

from parser.events import EventType
from detection.alert import Severity
from detection.enumeration import detect_enumeration
from conftest import make_event


def _user_attempts(users, ip="192.0.2.20"):
    """Verilen kullanici adlarinin her biri icin bir INVALID_USER olayi."""
    return [
        make_event(offset=i * 3, event_type=EventType.INVALID_USER, ip=ip, user=u)
        for i, u in enumerate(users)
    ]


def test_distinct_users_trigger():
    events = _user_attempts(["admin", "oracle", "postgres", "test", "ubuntu"])
    alerts = detect_enumeration(events, threshold=5)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "user_enumeration"
    assert a.count == 5
    assert a.source_ip == "192.0.2.20"


def test_below_threshold_no_alert():
    events = _user_attempts(["admin", "oracle", "postgres"])
    assert detect_enumeration(events, threshold=5) == []


def test_same_user_repeated_is_not_enumeration():
    # Ayni kullanici 10 kez -> benzersiz=1 -> enumeration DEGIL.
    events = [make_event(offset=i * 3, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.20", user="root")
              for i in range(10)]
    assert detect_enumeration(events, threshold=5) == []


def test_severity_high_at_double_threshold():
    # threshold=3, 6 farkli kullanici (2x) -> HIGH; tam esikte MEDIUM.
    med = detect_enumeration(_user_attempts(["a", "b", "c"]), threshold=3)[0]
    high = detect_enumeration(_user_attempts(["a", "b", "c", "d", "e", "f"]), threshold=3)[0]
    assert med.severity == Severity.MEDIUM
    assert high.severity == Severity.HIGH


def test_counts_unique_not_total():
    # 5 farkli kullanici + tekrarlar -> count benzersiz sayidir (5), toplam degil.
    events = _user_attempts(["admin", "oracle", "postgres", "test", "ubuntu"])
    events += _user_attempts(["admin", "oracle"])  # tekrar
    alerts = detect_enumeration(events, threshold=5)
    assert alerts[0].count == 5


# --------------------------------------------------------------------------- #
# KANIT (evidence) — cesitliligi gostermeli, ayni denemeyi tekrarlamamali
# --------------------------------------------------------------------------- #
def test_evidence_has_one_line_per_distinct_user():
    """
    sshd tipik olarak ayni deneme icin hem 'Invalid user X' hem 'Failed password
    for invalid user X' yazar. Eskiden her iki satir da kanita giriyordu; 10
    satirlik kanit yalnizca 5 farkli kullaniciyi gosteriyordu.
    """
    users = ["admin", "oracle", "postgres", "test", "ubuntu"]
    events = _user_attempts(users)
    # Ayni kullanicilar icin ikinci bir olay turu daha ekle (gercek sshd davranisi).
    events += [
        make_event(offset=100 + i, event_type=EventType.FAILED_PASSWORD,
                   ip="192.0.2.20", user=u)
        for i, u in enumerate(users)
    ]
    alert = detect_enumeration(events, threshold=5)[0]
    assert alert.count == 5
    assert len(alert.evidence) == 5              # 10 degil: kullanici basina bir satir
    assert len(set(alert.evidence)) == 5         # hepsi farkli


def test_evidence_capped_at_ten_distinct_users():
    events = _user_attempts([f"user{i}" for i in range(25)])
    alert = detect_enumeration(events, threshold=5)[0]
    assert alert.count == 25
    assert len(alert.evidence) == 10


def test_invalid_threshold_raises():
    import pytest
    with pytest.raises(ValueError, match="threshold"):
        detect_enumeration([], threshold=0)
