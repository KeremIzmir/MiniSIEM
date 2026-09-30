"""
test_su_fail_then_success.py — ayni (host, aktor, hedef) icin basarisiz su denemelerinin
ardindan util-linux su'nun kaydettigi basarili gecis.

Onemli kenar durumlar:
  - yalnizca TAM cift korele edilir: farkli aktor, hedef ya da host birlesmez
  - basaridan geriye KAPSAYICI pencere; eski basarisizliklar elenir
  - HER basari diziyi sifirlar (alarm uretse de uretmese de)
  - ayni zaman damgasinda girdi (log) sirasi korunur
  - count yalnizca basarisizliklari sayar; kanit en fazla 5 basarisizlik + basari
"""

import pytest

from parser.events import EventType
from detection.alert import Severity
from detection.su_fail_then_success import detect_su_fail_then_success
from conftest import make_event


def su(offset: float, kind=EventType.SU_FAILURE, actor="alice", target="root", host="web-01"):
    """SU_FAILURE ya da SU_SUCCESS: yerel oldugu icin IP/port yok."""
    e = make_event(offset=offset, event_type=kind, ip=None, user=target, host=host, process="su")
    e.port = None
    e.actor_username = actor
    return e


def fails(n, step=10.0, start=0.0, **kw):
    return [su(start + i * step, **kw) for i in range(n)]


def ok(offset, **kw):
    return su(offset, kind=EventType.SU_SUCCESS, **kw)


# --- esik, severity, count ---------------------------------------------------- #

def test_below_min_fails_no_alert():
    assert detect_su_fail_then_success(fails(2) + [ok(30)]) == []


def test_exact_min_fails_one_high_alert():
    alerts = detect_su_fail_then_success(fails(3) + [ok(40)])
    assert len(alerts) == 1
    assert (alerts[0].severity, alerts[0].count) == (Severity.HIGH, 3)


def test_more_than_min_fails_still_one_high_alert():
    alerts = detect_su_fail_then_success(fails(7) + [ok(80)])
    assert len(alerts) == 1
    assert (alerts[0].severity, alerts[0].count) == (Severity.HIGH, 7)


def test_count_is_failures_only():
    a = detect_su_fail_then_success(fails(4) + [ok(50)])[0]
    assert a.count == 4                     # basari dahil degil


# --- pencere ------------------------------------------------------------------ #

def test_exact_window_boundary_is_inclusive():
    # basari - ilk basarisizlik == window -> dahil
    events = [su(0), su(100), su(200), ok(600)]
    a = detect_su_fail_then_success(events, window=600)
    assert len(a) == 1 and a[0].count == 3


def test_window_plus_one_excludes_oldest_failure():
    events = [su(0), su(100), su(200), ok(601)]
    assert detect_su_fail_then_success(events, window=600) == []


def test_stale_failures_are_excluded():
    # iki eski (saatler once) + iki yeni basarisizlik: esik 3'e ulasilmaz.
    events = [su(0), su(10), su(7200), su(7210), ok(7220)]
    assert detect_su_fail_then_success(events) == []


def test_unordered_input_distinct_timestamps_same_result():
    ordered = fails(3) + [ok(40)]
    shuffled = [ordered[3], ordered[1], ordered[0], ordered[2]]
    a, b = detect_su_fail_then_success(ordered)[0], detect_su_fail_then_success(shuffled)[0]
    assert (a.count, a.time_window, a.description, a.evidence) == (b.count, b.time_window, b.description, b.evidence)


# --- tam cift gruplama ---------------------------------------------------------- #

def test_same_host_actor_target_correlates():
    assert len(detect_su_fail_then_success(fails(3, actor="alice", target="root") + [ok(40)])) == 1


def test_different_actor_is_separated():
    events = fails(2, actor="alice") + [su(25, actor="bob"), ok(40, actor="alice")]
    assert detect_su_fail_then_success(events) == []


def test_different_target_is_separated():
    # alice -> root x3 basarisiz, ardindan postgres'e basarili: korelasyon YOK.
    assert detect_su_fail_then_success(fails(3, target="root") + [ok(40, target="postgres")]) == []


def test_target_switching_success_needs_its_own_failures():
    events = [su(0, target="root"), su(10, target="postgres"), su(20, target="deploy"), ok(30, target="deploy")]
    assert detect_su_fail_then_success(events) == []


def test_different_host_is_separated():
    assert detect_su_fail_then_success(fails(3, host="web-01") + [ok(40, host="db-01")]) == []


def test_missing_actor_is_skipped():
    assert detect_su_fail_then_success(fails(3, actor=None) + [ok(40, actor=None)]) == []


def test_missing_target_is_skipped_defensively():
    assert detect_su_fail_then_success(fails(3, target=None) + [ok(40, target=None)]) == []


# --- olay turleri -------------------------------------------------------------- #

@pytest.mark.parametrize("etype", [EventType.AUTH_FAILURE, EventType.SUDO_FAILURE, EventType.FAILED_PASSWORD])
def test_other_failure_types_are_not_counted(etype):
    others = [su(i * 10, kind=etype) for i in range(3)]
    assert detect_su_fail_then_success(others + [ok(40)]) == []


def test_only_su_success_triggers():
    # ACCEPTED_LOGIN (is_success=True) su korelasyonunu TETIKLEMEZ.
    events = fails(3) + [su(40, kind=EventType.ACCEPTED_LOGIN)]
    assert detect_su_fail_then_success(events) == []


def test_unknown_events_are_ignored():
    events = fails(3) + [su(35, kind=EventType.UNKNOWN), ok(40)]
    a = detect_su_fail_then_success(events)[0]
    assert a.count == 3


# --- sifirlama ve coklu diziler ------------------------------------------------ #

def test_success_resets_sequence():
    # 3 basarisizlik + basari (alarm), sonra 2 basarisizlik + basari: ikinci alarm YOK.
    events = fails(3) + [ok(40)] + fails(2, start=100) + [ok(130)]
    alerts = detect_su_fail_then_success(events)
    assert len(alerts) == 1 and alerts[0].count == 3


def test_below_threshold_success_also_resets():
    # 2 basarisizlik + basari (alarm yok, ama sifirlar) + 1 basarisizlik + basari: alarm YOK.
    events = fails(2) + [ok(30)] + [su(40), ok(50)]
    assert detect_su_fail_then_success(events) == []


def test_two_independent_valid_sequences_two_alerts():
    events = fails(3) + [ok(40)] + fails(4, start=1000) + [ok(1050)]
    alerts = detect_su_fail_then_success(events)
    assert [a.count for a in alerts] == [3, 4]


def test_first_success_prevents_old_failures_leaking():
    first = fails(3) + [ok(40)]
    second_fail = su(50)
    second_ok = ok(60)
    alerts = detect_su_fail_then_success(first + [second_fail, second_ok])
    assert len(alerts) == 1
    assert second_fail.raw_line not in alerts[0].evidence


# --- kanit ve alarm sekli ------------------------------------------------------ #

def test_evidence_is_last_five_failures_plus_success():
    fl = fails(8)
    success = ok(100)
    a = detect_su_fail_then_success(fl + [success])[0]
    assert a.count == 8                                      # count kanittan buyuk olabilir
    assert a.evidence == [e.raw_line for e in fl[-5:]] + [success.raw_line]


def test_evidence_is_chronological():
    fl = fails(3)
    success = ok(40)
    a = detect_su_fail_then_success([success] + list(reversed(fl)))[0]
    assert a.evidence == [e.raw_line for e in fl] + [success.raw_line]


def test_alert_shape():
    a = detect_su_fail_then_success([su(0), su(90), su(180), ok(180)])[0]
    assert a.rule_name == "su_fail_then_success"
    assert a.source_ip is None
    assert a.time_window == "05:00:00-05:03:00 (180s)"
    assert a.description == (
        "alice@web-01: root hesabina 180 saniye icinde 3 basarisiz su denemesinin ardindan "
        "basarili su gecisi kaydedildi. Olasi basarili yerel hesap gecisi - acil incele."
    )


# --- ayni zaman damgasi: girdi (log) sirasi korunur ------------------------------ #

def test_same_timestamp_failure_before_success_counts():
    events = [su(0), su(10), su(20), ok(20)]            # son basarisizlik ve basari ayni saniye
    a = detect_su_fail_then_success(events)
    assert len(a) == 1 and a[0].count == 3


def test_same_timestamp_success_before_failure_starts_new_sequence():
    events = [su(0), su(10), ok(20), su(20)]            # basari once: sonraki basarisizlik yeni dizi
    assert detect_su_fail_then_success(events) == []


def test_input_list_is_not_mutated():
    events = [ok(40)] + fails(3)
    snapshot = list(events)
    detect_su_fail_then_success(events)
    assert events == snapshot


# --- gecersiz ayar -------------------------------------------------------------- #

@pytest.mark.parametrize("kwargs", [{"min_fails": 0}, {"window": -1}])
def test_invalid_config_rejected_even_with_empty_events(kwargs):
    with pytest.raises(ValueError):
        detect_su_fail_then_success([], **kwargs)
