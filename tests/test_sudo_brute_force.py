"""
test_sudo_brute_force.py — ayni host'ta ayni kullanicinin tekrarlanan basarisiz sudo denemeleri.

Onemli kenar durumlar:
  - esigin altinda alarm YOK; esikte MEDIUM, 2x esikte HIGH
  - pencere KAPSAYICI: fark == window ayni pencerede, window+1 degil
  - (host, username) gruplari asla birlesmez
  - girdi sirasi sonucu degistirmez
  - yalnizca SUDO_FAILURE sayilir
  - gecersiz ayar, olay olmasa bile reddedilir
"""

import pytest

from parser.events import EventType
from detection.alert import Severity
from detection.sudo_brute_force import detect_sudo_brute_force
from conftest import make_event


def sudo_fail(offset: float = 0.0, user="bob", host: str = "web-01"):
    """Tek bir SUDO_FAILURE olayi: yerel oldugu icin IP ve port yok."""
    e = make_event(offset=offset, event_type=EventType.SUDO_FAILURE, ip=None,
                   user=user, host=host, process="sudo")
    e.port = None
    return e


def sudo_fails(n: int, step: float = 5.0, start: float = 0.0, user="bob", host: str = "web-01"):
    """'step' saniye arayla n adet SUDO_FAILURE."""
    return [sudo_fail(start + i * step, user=user, host=host) for i in range(n)]


# --- esik ve severity -------------------------------------------------------- #

def test_below_threshold_no_alert():
    assert detect_sudo_brute_force(sudo_fails(2)) == []


def test_at_threshold_one_medium_alert():
    alerts = detect_sudo_brute_force(sudo_fails(3))
    assert len(alerts) == 1
    assert alerts[0].count == 3
    assert alerts[0].severity == Severity.MEDIUM


def test_just_below_double_threshold_is_medium():
    alerts = detect_sudo_brute_force(sudo_fails(5))
    assert alerts[0].count == 5
    assert alerts[0].severity == Severity.MEDIUM


def test_double_threshold_is_high():
    alerts = detect_sudo_brute_force(sudo_fails(6))
    assert alerts[0].count == 6
    assert alerts[0].severity == Severity.HIGH


def test_severity_scales_with_custom_threshold():
    # esik 2: 2-3 MEDIUM, 4+ HIGH
    assert detect_sudo_brute_force(sudo_fails(3), threshold=2)[0].severity == Severity.MEDIUM
    assert detect_sudo_brute_force(sudo_fails(4), threshold=2)[0].severity == Severity.HIGH


# --- kayan pencere ----------------------------------------------------------- #

def test_failures_inside_window_alert():
    # 3 deneme, 0-280 sn arasina yayilmis: 300 sn'lik pencereye sigar.
    assert len(detect_sudo_brute_force(sudo_fails(3, step=140))) == 1


def test_failures_spread_beyond_window_no_alert():
    # 0, 200, 400: hicbir 300 sn'lik pencerede 3 olay birikmez.
    assert detect_sudo_brute_force(sudo_fails(3, step=200)) == []


def test_exact_window_boundary_is_inclusive():
    # ilk ile son arasi tam 300 sn -> ayni pencere.
    events = [sudo_fail(0), sudo_fail(150), sudo_fail(300)]
    alerts = detect_sudo_brute_force(events, window=300)
    assert len(alerts) == 1
    assert alerts[0].count == 3


def test_window_plus_one_is_outside():
    events = [sudo_fail(0), sudo_fail(150), sudo_fail(301)]
    assert detect_sudo_brute_force(events, window=300) == []


def test_window_parameter_is_honored():
    # 3 deneme 10 sn arayla (toplam 20 sn): window=19 ile sigmaz, 20 ile sigar.
    events = sudo_fails(3, step=10)
    assert detect_sudo_brute_force(events, window=19) == []
    assert len(detect_sudo_brute_force(events, window=20)) == 1


# --- gruplama ------------------------------------------------------------------ #

def test_same_user_different_hosts_do_not_combine():
    events = sudo_fails(2, host="web-01") + sudo_fails(2, host="web-02")
    assert detect_sudo_brute_force(events) == []


def test_different_users_same_host_do_not_combine():
    events = sudo_fails(2, user="alice") + sudo_fails(2, user="bob")
    assert detect_sudo_brute_force(events) == []


def test_two_independent_groups_two_alerts():
    events = sudo_fails(3, user="alice", host="web-01") + sudo_fails(4, user="bob", host="db-01")
    alerts = detect_sudo_brute_force(events)
    assert len(alerts) == 2
    by_desc = {a.count: a.description for a in alerts}
    assert by_desc[3].startswith("alice@web-01:")
    assert by_desc[4].startswith("bob@db-01:")


def test_one_alert_per_group_even_with_many_windows():
    # Iki ayri yogun kume (aralarinda 1 saat): grup basina yine TEK alarm.
    events = sudo_fails(3) + sudo_fails(4, start=3600)
    alerts = detect_sudo_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].count == 4          # en yogun pencere


def test_unordered_input_same_result():
    ordered = sudo_fails(4, step=30)
    shuffled = [ordered[2], ordered[0], ordered[3], ordered[1]]
    a, b = detect_sudo_brute_force(ordered)[0], detect_sudo_brute_force(shuffled)[0]
    assert (a.count, a.severity, a.time_window, a.evidence) == (b.count, b.severity, b.time_window, b.evidence)


# --- sayilan olay turleri ----------------------------------------------------- #

def test_only_sudo_failure_is_counted():
    others = [
        make_event(0, event_type=EventType.AUTH_FAILURE, ip=None, user="bob", process="su"),
        make_event(1, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.1", user="bob"),
        make_event(2, event_type=EventType.UNKNOWN, ip=None, user="bob", process="sudo"),
    ]
    # 2 sudo + 3 baska tur ayni kullanici/host: esik 3'e ulasmamali.
    assert detect_sudo_brute_force(sudo_fails(2) + others) == []


@pytest.mark.parametrize("etype", [EventType.AUTH_FAILURE, EventType.FAILED_PASSWORD, EventType.UNKNOWN])
def test_other_event_types_alone_ignored(etype):
    events = [make_event(i, event_type=etype, ip=None, user="bob", process="sudo") for i in range(10)]
    assert detect_sudo_brute_force(events) == []


def test_events_without_username_ignored():
    assert detect_sudo_brute_force(sudo_fails(5, user=None)) == []


# --- kanit ve alarm sekli ----------------------------------------------------- #

def test_evidence_comes_from_densest_window():
    # Seyrek baslangic (0, 1000) + yogun kume (2000, 2005, 2010, 2015).
    sparse = [sudo_fail(0), sudo_fail(1000)]
    dense = sudo_fails(4, start=2000)
    alerts = detect_sudo_brute_force(sparse + dense)
    assert alerts[0].count == 4
    assert alerts[0].evidence == [e.raw_line for e in dense]


def test_evidence_is_chronological():
    events = sudo_fails(4, step=10)
    alerts = detect_sudo_brute_force(list(reversed(events)))
    assert alerts[0].evidence == [e.raw_line for e in events]


def test_evidence_capped_at_ten_lines():
    events = sudo_fails(15, step=2)
    alerts = detect_sudo_brute_force(events)
    assert alerts[0].count == 15
    assert alerts[0].evidence == [e.raw_line for e in events[:10]]


def test_alert_shape():
    a = detect_sudo_brute_force(sudo_fails(3, step=6))[0]
    assert a.rule_name == "sudo_brute_force"
    assert a.source_ip is None
    assert a.time_window == "05:00:00-05:00:12 (12s)"
    assert a.description.startswith("bob@web-01: 12 saniyede 3 basarisiz sudo")
    assert "esik=3/300s" in a.description


# --- gecersiz ayar ------------------------------------------------------------ #

@pytest.mark.parametrize("events", [[], None], ids=["empty", "with-events"])
def test_negative_window_rejected(events):
    with pytest.raises(ValueError):
        detect_sudo_brute_force(events if events is not None else sudo_fails(3), window=-1)


@pytest.mark.parametrize("events", [[], None], ids=["empty", "with-events"])
def test_zero_threshold_rejected(events):
    with pytest.raises(ValueError):
        detect_sudo_brute_force(events if events is not None else sudo_fails(3), threshold=0)
