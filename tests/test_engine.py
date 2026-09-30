"""
test_engine.py — tum kurallari calistiran motor: allowlist ve siralama.
"""

from parser.events import EventType
from detection.alert import Severity
from detection.engine import run_detections
from conftest import make_event, make_failures


def test_allowlist_filters_before_detection():
    # Guvenilir IP'den 8 basarisizlik -> allowlist'teyse alarm uretmemeli.
    events = make_failures(8, ip="198.51.100.5", step=5)
    assert run_detections(events, threshold=5) != []          # allowlist yokken alarm var
    assert run_detections(events, threshold=5, allowlist=["198.51.100.5"]) == []


def test_alerts_sorted_high_before_low():
    # Yuksek oncelikli (fail_then_success=HIGH) ile dusuk (brute_force=LOW) karisik uret.
    events = []
    # IP .30: 3 basarisiz + basari -> fail_then_success (HIGH)
    events += [make_event(offset=o, event_type=t, ip="192.0.2.30") for o, t in [
        (0, EventType.FAILED_PASSWORD), (8, EventType.FAILED_PASSWORD),
        (16, EventType.FAILED_PASSWORD), (24, EventType.ACCEPTED_LOGIN),
    ]]
    # IP .10: 5 basarisiz -> brute_force (LOW)
    events += make_failures(5, ip="192.0.2.10", step=5)

    alerts = run_detections(events, window=300, threshold=5)
    ranks = [a.severity.rank for a in alerts]
    assert ranks == sorted(ranks, reverse=True)               # azalan: high once
    assert alerts[0].severity == Severity.HIGH


def test_empty_events_no_alerts():
    assert run_detections([]) == []


# --------------------------------------------------------------------------- #
# PARAMETRE BAGLANTISI — her ayar DOGRU kurala ulasmali
# --------------------------------------------------------------------------- #
import pytest

from detection.alert import Severity as _Sev


def _fts_events(ip="192.0.2.30"):
    """3 basarisizlik + 24s sonra basari -> fail_then_success tetikleyicisi."""
    return [make_event(offset=o, event_type=t, ip=ip) for o, t in [
        (0, EventType.FAILED_PASSWORD), (8, EventType.FAILED_PASSWORD),
        (16, EventType.FAILED_PASSWORD), (24, EventType.ACCEPTED_LOGIN),
    ]]


def _rules(alerts):
    return {a.rule_name for a in alerts}


def test_min_fails_reaches_fail_then_success():
    events = _fts_events()
    assert "fail_then_success" in _rules(run_detections(events, min_fails=3))
    assert "fail_then_success" not in _rules(run_detections(events, min_fails=4))


def test_success_window_reaches_fail_then_success():
    events = _fts_events()
    assert "fail_then_success" in _rules(run_detections(events, success_window=600))
    # Pencere 10s: 0/8/16. saniyedeki basarisizliklarin yalnizca sonuncusu kalir.
    assert "fail_then_success" not in _rules(run_detections(events, success_window=10))


def test_anomaly_k_and_min_volume_reach_anomaly_rule():
    events = []
    o = 0
    for ip, vol in {"192.0.2.1": 30, "192.0.2.2": 1, "192.0.2.3": 1, "192.0.2.4": 1}.items():
        for _ in range(vol):
            events.append(make_event(offset=o, ip=ip)); o += 1
    assert "anomalous_ip" in _rules(run_detections(events, anomaly_k=2.0))
    assert "anomalous_ip" not in _rules(run_detections(events, anomaly_k=1000.0))
    # min_volume freni: mutlak hacim esigin altindaysa hic degerlendirme.
    assert "anomalous_ip" not in _rules(run_detections(events, anomaly_min_volume=100))


def test_brute_force_params_reach_rule():
    events = make_failures(6, ip="192.0.2.10", step=5)
    assert "brute_force" in _rules(run_detections(events, threshold=5))
    assert "brute_force" not in _rules(run_detections(events, threshold=7))
    # Pencere daraltilirsa ayni olaylar artik tek pencereye sigmaz.
    assert "brute_force" not in _rules(run_detections(events, window=1, threshold=5))


def test_enum_threshold_reaches_rule():
    events = [make_event(offset=i * 3, event_type=EventType.INVALID_USER,
                         ip="192.0.2.20", user=u)
              for i, u in enumerate(["a", "b", "c", "d", "e"])]
    assert "user_enumeration" in _rules(run_detections(events, enum_threshold=5))
    assert "user_enumeration" not in _rules(run_detections(events, enum_threshold=6))


def test_invalid_config_propagates_as_valueerror():
    """Motor gecersiz ayari yutmamali; cagiran taraf (CLI) bunu kullanim hatasi yapar."""
    with pytest.raises(ValueError):
        run_detections(make_failures(6), window=-1)


def _sudo_events(n=3, step=10):
    """Ayni host+kullanicidan 'step' saniye arayla n SUDO_FAILURE (yerel: IP yok)."""
    return [make_event(offset=i * step, event_type=EventType.SUDO_FAILURE, ip=None,
                       user="bob", process="sudo") for i in range(n)]


def test_sudo_rule_runs_with_defaults():
    assert "sudo_brute_force" in _rules(run_detections(_sudo_events(3)))


def test_sudo_threshold_reaches_rule():
    assert "sudo_brute_force" not in _rules(run_detections(_sudo_events(3), sudo_threshold=4))


def test_sudo_window_reaches_rule():
    # 3 olay 10s arayla (toplam 20s): sudo_window=19 ile sigmaz.
    events = _sudo_events(3, step=10)
    assert "sudo_brute_force" in _rules(run_detections(events, sudo_window=20))
    assert "sudo_brute_force" not in _rules(run_detections(events, sudo_window=19))


@pytest.mark.parametrize("kwargs", [{"sudo_threshold": 0}, {"sudo_window": -1}])
def test_invalid_sudo_config_propagates_as_valueerror(kwargs):
    with pytest.raises(ValueError):
        run_detections([], **kwargs)


def test_ip_allowlist_does_not_suppress_sudo_alerts():
    # IP allowlist yalnizca ag kaynakli olaylari eler; sudo olaylarinda IP yoktur.
    alerts = run_detections(_sudo_events(3), allowlist=["192.0.2.1", "198.51.100.5"])
    assert "sudo_brute_force" in _rules(alerts)


def test_sort_is_stable_by_severity_then_count():
    events = _fts_events() + make_failures(6, ip="192.0.2.10", step=5)
    alerts = run_detections(events, threshold=5)
    keys = [(-a.severity.rank, -a.count) for a in alerts]
    assert keys == sorted(keys)
    assert alerts[0].severity == _Sev.HIGH


def _su_events(n=3, step=10, actor="alice", ip=None, targets=("root",)):
    """Ayni host+aktorden 'step' saniye arayla n SU_FAILURE (hedefler dongusel)."""
    out = []
    for i in range(n):
        e = make_event(offset=i * step, event_type=EventType.SU_FAILURE, ip=ip,
                       user=targets[i % len(targets)], process="su")
        e.actor_username = actor
        out.append(e)
    return out


def test_su_rule_runs_with_defaults():
    assert "su_brute_force" in _rules(run_detections(_su_events(3)))


def test_su_threshold_reaches_rule():
    assert "su_brute_force" not in _rules(run_detections(_su_events(3), su_threshold=4))


def test_su_window_reaches_rule():
    events = _su_events(3, step=10)                   # toplam 20s
    assert "su_brute_force" in _rules(run_detections(events, su_window=20))
    assert "su_brute_force" not in _rules(run_detections(events, su_window=19))


@pytest.mark.parametrize("kwargs", [{"su_threshold": 0}, {"su_window": -1}])
def test_invalid_su_config_propagates_as_valueerror(kwargs):
    with pytest.raises(ValueError):
        run_detections([], **kwargs)


def test_local_su_events_survive_ip_allowlist():
    # Tipik yerel su: source_ip None -> IP allowlist bu olaylari suzemez.
    alerts = run_detections(_su_events(3), allowlist=["192.0.2.1", "198.51.100.5"])
    assert "su_brute_force" in _rules(alerts)


def test_su_events_with_real_source_ip_follow_existing_allowlist():
    # Olayda gercekten bir kaynak IP varsa engine on-filtresi (mevcut davranis) gecerlidir.
    events = _su_events(3, ip="198.51.100.5")
    assert "su_brute_force" in _rules(run_detections(events))
    assert "su_brute_force" not in _rules(run_detections(events, allowlist=["198.51.100.5"]))
