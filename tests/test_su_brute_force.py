"""
test_su_brute_force.py — ayni host'ta ayni yerel aktorun tekrarlanan basarisiz su denemeleri.

Onemli kenar durumlar:
  - gruplama (host, AKTOR): ayni aktorun farkli hedeflere denemeleri BIRLESIR,
    farkli aktorlerin ayni hedefe denemeleri BIRLESMEZ
  - aktoru bilinmeyen olay sayilmaz (hedef asla aktor yerine kullanilmaz)
  - pencere KAPSAYICI; girdi sirasi sonucu degistirmez
  - hedef listesi en yogun pencereden, sirali, en fazla 5
  - gecersiz ayar, olay olmasa bile reddedilir
"""

import pytest

from parser.events import EventType
from detection.alert import Severity
from detection.su_brute_force import detect_su_brute_force
from conftest import make_event


def su_fail(offset: float = 0.0, actor="alice", target="root", host: str = "web-01"):
    """Tek bir SU_FAILURE: yerel oldugu icin IP/port yok; aktor ayri alanda."""
    e = make_event(offset=offset, event_type=EventType.SU_FAILURE, ip=None,
                   user=target, host=host, process="su")
    e.port = None
    e.actor_username = actor
    return e


def su_fails(n: int, step: float = 5.0, start: float = 0.0, actor="alice", target="root",
             host: str = "web-01"):
    return [su_fail(start + i * step, actor=actor, target=target, host=host) for i in range(n)]


# --- esik ve severity -------------------------------------------------------- #

def test_below_threshold_no_alert():
    assert detect_su_brute_force(su_fails(2)) == []


def test_at_threshold_one_medium_alert():
    alerts = detect_su_brute_force(su_fails(3))
    assert len(alerts) == 1
    assert (alerts[0].count, alerts[0].severity) == (3, Severity.MEDIUM)


def test_just_below_double_threshold_is_medium():
    assert detect_su_brute_force(su_fails(5))[0].severity == Severity.MEDIUM


def test_double_threshold_is_high():
    alerts = detect_su_brute_force(su_fails(6))
    assert (alerts[0].count, alerts[0].severity) == (6, Severity.HIGH)


# --- kayan pencere ----------------------------------------------------------- #

def test_failures_inside_window_alert():
    assert len(detect_su_brute_force(su_fails(3, step=140))) == 1


def test_exact_window_boundary_is_inclusive():
    events = [su_fail(0), su_fail(150), su_fail(300)]
    alerts = detect_su_brute_force(events, window=300)
    assert len(alerts) == 1 and alerts[0].count == 3


def test_window_plus_one_is_outside():
    assert detect_su_brute_force([su_fail(0), su_fail(150), su_fail(301)], window=300) == []


def test_unordered_input_same_result():
    ordered = su_fails(4, step=30)
    shuffled = [ordered[2], ordered[0], ordered[3], ordered[1]]
    a, b = detect_su_brute_force(ordered)[0], detect_su_brute_force(shuffled)[0]
    assert (a.count, a.severity, a.time_window, a.description, a.evidence) == \
           (b.count, b.severity, b.time_window, b.description, b.evidence)


# --- gruplama: host ve AKTOR ------------------------------------------------- #

def test_same_actor_different_hosts_do_not_combine():
    assert detect_su_brute_force(su_fails(2, host="web-01") + su_fails(2, host="db-01")) == []


def test_different_actors_same_target_do_not_combine():
    # alice, bob, charlie -> root birer kez: uc ayri aktor, hicbiri esige ulasmaz.
    events = [su_fail(0, actor="alice"), su_fail(5, actor="bob"), su_fail(10, actor="charlie")]
    assert detect_su_brute_force(events) == []


def test_same_actor_same_target_combines():
    alerts = detect_su_brute_force(su_fails(3, actor="alice", target="root"))
    assert len(alerts) == 1
    assert "hedefler: root;" in alerts[0].description


def test_same_actor_different_targets_combines():
    # Hedef degistiren aktor tek grupta: alice -> root, postgres, deploy.
    events = [su_fail(0, target="root"), su_fail(5, target="postgres"), su_fail(10, target="deploy")]
    alerts = detect_su_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].count == 3
    assert alerts[0].description.startswith("alice@web-01:")


def test_two_independent_actor_groups_two_alerts():
    events = su_fails(3, actor="alice", host="web-01") + su_fails(4, actor="bob", host="db-01")
    by_count = {a.count: a.description for a in detect_su_brute_force(events)}
    assert set(by_count) == {3, 4}
    assert by_count[3].startswith("alice@web-01:")
    assert by_count[4].startswith("bob@db-01:")


# --- sayilan olay turleri ve eksik kimlik ------------------------------------ #

def test_only_su_failure_is_counted():
    others = [make_event(i, event_type=t, ip=None, user="root", process="su")
              for i, t in enumerate([EventType.AUTH_FAILURE, EventType.SUDO_FAILURE,
                                     EventType.FAILED_PASSWORD, EventType.UNKNOWN])]
    for e in others:
        e.actor_username = "alice"
    assert detect_su_brute_force(su_fails(2) + others) == []


@pytest.mark.parametrize("etype", [EventType.AUTH_FAILURE, EventType.SUDO_FAILURE,
                                   EventType.FAILED_PASSWORD, EventType.UNKNOWN])
def test_other_event_types_alone_ignored(etype):
    events = [make_event(i, event_type=etype, ip=None, user="root", process="su") for i in range(10)]
    for e in events:
        e.actor_username = "alice"
    assert detect_su_brute_force(events) == []


def test_events_without_actor_are_skipped():
    # Aktor bilinmiyorsa olay sayilmaz; hedef ('root') ASLA aktor yerine gecmez.
    assert detect_su_brute_force(su_fails(5, actor=None)) == []


# --- hedef listesi ----------------------------------------------------------- #

def test_targets_are_sorted_and_unique():
    events = [su_fail(0, target="root"), su_fail(5, target="deploy"),
              su_fail(10, target="root"), su_fail(15, target="postgres")]
    assert "hedefler: deploy, postgres, root;" in detect_su_brute_force(events)[0].description


def test_targets_capped_at_five_with_remainder():
    names = ["h", "g", "f", "e", "d", "c", "b", "a"]          # 8 benzersiz hedef
    events = [su_fail(i * 5, target=n) for i, n in enumerate(names)]
    d = detect_su_brute_force(events)[0].description
    assert "hedefler: a, b, c, d, e (+3 daha);" in d


def test_targets_come_from_densest_window_only():
    # Eski ve seyrek 'old1', 'old2' hedefleri yogun pencerede yok -> listede olmamali.
    sparse = [su_fail(0, target="old1"), su_fail(1000, target="old2")]
    dense = [su_fail(2000 + i * 5, target=t) for i, t in enumerate(["root", "postgres", "root"])]
    d = detect_su_brute_force(sparse + dense)[0].description
    assert "hedefler: postgres, root;" in d
    assert "old1" not in d and "old2" not in d


def test_missing_target_does_not_crash():
    events = su_fails(3, target=None)
    assert "hedefler: bilinmiyor;" in detect_su_brute_force(events)[0].description


# --- kanit ve alarm sekli ----------------------------------------------------- #

def test_evidence_comes_from_densest_window():
    sparse = [su_fail(0), su_fail(1000)]
    dense = su_fails(4, start=2000)
    alerts = detect_su_brute_force(sparse + dense)
    assert alerts[0].count == 4
    assert alerts[0].evidence == [e.raw_line for e in dense]


def test_evidence_is_chronological():
    events = su_fails(4, step=10)
    assert detect_su_brute_force(list(reversed(events)))[0].evidence == [e.raw_line for e in events]


def test_evidence_capped_at_ten_lines():
    events = su_fails(15, step=2)
    alerts = detect_su_brute_force(events)
    assert alerts[0].count == 15
    assert alerts[0].evidence == [e.raw_line for e in events[:10]]


def test_alert_shape():
    a = detect_su_brute_force(su_fails(3, step=6))[0]
    assert a.rule_name == "su_brute_force"
    assert a.source_ip is None
    assert a.time_window == "05:00:00-05:00:12 (12s)"
    assert a.description == (
        "alice@web-01: 12 saniyede 3 basarisiz su kimlik dogrulamasi "
        "(hedefler: root; esik=3/300s). Olasi yerel hesap gecisi veya parola tahmin aktivitesi."
    )


# --- gecersiz ayar ------------------------------------------------------------ #

@pytest.mark.parametrize("events", [[], None], ids=["empty", "with-events"])
def test_negative_window_rejected(events):
    with pytest.raises(ValueError):
        detect_su_brute_force(events if events is not None else su_fails(3), window=-1)


@pytest.mark.parametrize("events", [[], None], ids=["empty", "with-events"])
def test_zero_threshold_rejected(events):
    with pytest.raises(ValueError):
        detect_su_brute_force(events if events is not None else su_fails(3), threshold=0)
