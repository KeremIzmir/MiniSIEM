"""
test_fail_then_success.py — "cok basarisiz, sonra basarili" kalibi (HIGH).

En tehlikeli senaryo: ardisik basarisizliklardan sonra ACCEPTED gelirse,
brute-force MUHTEMELEN BASARMISTIR. Kenar durumlar:
  - yeterli basarisizlik + penceredeki basari -> HIGH alarm
  - basari cok gec geldiyse (gap > window) -> alarm YOK (mesru kullanici)
  - min_fails altinda -> alarm YOK
  - basari sayaci sifirlar (sonraki diziye karismaz)
"""

from parser.events import EventType
from detection.alert import Severity
from detection.fail_then_success import detect_fail_then_success
from conftest import make_event


def _seq(specs, ip="192.0.2.30"):
    """[(offset, EventType), ...] -> Event listesi."""
    return [make_event(offset=o, event_type=t, ip=ip) for o, t in specs]


def test_fails_then_success_triggers_high():
    events = _seq([
        (0, EventType.FAILED_PASSWORD),
        (8, EventType.FAILED_PASSWORD),
        (16, EventType.FAILED_PASSWORD),
        (24, EventType.ACCEPTED_LOGIN),   # 3 basarisiz sonra basari, 24s sonra
    ])
    alerts = detect_fail_then_success(events, min_fails=3, window=600)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "fail_then_success"
    assert a.severity == Severity.HIGH
    assert a.count == 3
    # Kanit: basarisizliklar + basari satiri dahil.
    assert any("ACCEPTED_LOGIN" in line for line in a.evidence)


def test_success_too_late_no_alert():
    # Son basarisizlik ile basari arasinda 700s var (>600 pencere) -> alarm yok.
    events = _seq([
        (0, EventType.FAILED_PASSWORD),
        (8, EventType.FAILED_PASSWORD),
        (16, EventType.FAILED_PASSWORD),
        (716, EventType.ACCEPTED_LOGIN),
    ])
    assert detect_fail_then_success(events, min_fails=3, window=600) == []


def test_too_few_fails_no_alert():
    events = _seq([
        (0, EventType.FAILED_PASSWORD),
        (8, EventType.FAILED_PASSWORD),
        (16, EventType.ACCEPTED_LOGIN),   # sadece 2 basarisiz
    ])
    assert detect_fail_then_success(events, min_fails=3, window=600) == []


def test_success_resets_streak():
    # Ilk basari sayaci sifirlar; sonraki tek basarisizlik+basari tetiklemez.
    events = _seq([
        (0, EventType.FAILED_PASSWORD),
        (8, EventType.FAILED_PASSWORD),
        (16, EventType.FAILED_PASSWORD),
        (24, EventType.ACCEPTED_LOGIN),    # 1. tetikleyici
        (32, EventType.FAILED_PASSWORD),
        (40, EventType.ACCEPTED_LOGIN),    # streak=1 -> tetiklemez
    ])
    alerts = detect_fail_then_success(events, min_fails=3, window=600)
    assert len(alerts) == 1


def test_clean_success_only_no_alert():
    events = _seq([(0, EventType.ACCEPTED_LOGIN)])
    assert detect_fail_then_success(events) == []


# --------------------------------------------------------------------------- #
# PENCERE SEMANTIGI — pencere basarisizliklara uygulanir, sadece sonuncusuna degil
# --------------------------------------------------------------------------- #
import pytest


def test_stale_failures_outside_window_are_not_counted():
    """
    Eskiden pencere SADECE son basarisizliga bakiyordu; boylece 30 gun onceki
    basarisizliklar da sayima girip sahte 'basarili brute-force' uretiyordu.
    """
    events = _seq([
        (0, EventType.FAILED_PASSWORD),           # 30 gun once
        (1, EventType.FAILED_PASSWORD),           # 30 gun once
        (86400 * 30, EventType.FAILED_PASSWORD),  # bugun: tek basarisizlik
        (86400 * 30 + 10, EventType.ACCEPTED_LOGIN),
    ])
    # Pencere icinde yalnizca 1 basarisizlik var -> min_fails=3 karsilanmiyor.
    assert detect_fail_then_success(events, min_fails=3, window=600) == []


def test_count_and_evidence_reflect_only_windowed_failures():
    events = _seq([
        (0, EventType.FAILED_PASSWORD),           # pencere disi
        (86400, EventType.FAILED_PASSWORD),
        (86400 + 8, EventType.FAILED_PASSWORD),
        (86400 + 16, EventType.FAILED_PASSWORD),
        (86400 + 24, EventType.ACCEPTED_LOGIN),
    ])
    alerts = detect_fail_then_success(events, min_fails=3, window=600)
    assert len(alerts) == 1
    assert alerts[0].count == 3               # 4 degil: en eski basarisizlik elendi
    assert "(24s)" in alerts[0].time_window   # pencere gercek suresi anlatir


def test_invalid_parameters_raise():
    with pytest.raises(ValueError, match="min_fails"):
        detect_fail_then_success([], min_fails=0)
    with pytest.raises(ValueError, match="window"):
        detect_fail_then_success([], window=-1)
