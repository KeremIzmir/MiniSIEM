"""
test_brute_force.py — kayan pencere brute-force tespiti.

Onemli kenar durumlar:
  - esigin altinda alarm YOK
  - esikte/ustunde alarm VAR
  - olaylar pencereye yayilirsa (zamanda uzaksa) alarm YOK (sliding window mantigi)
  - asilma miktarina gore severity tirmanir
  - sadece FAILED_PASSWORD sayilir (INVALID_USER enumeration'in isi)
"""

from parser.events import EventType
from detection.alert import Severity
from detection.brute_force import detect_brute_force
from conftest import make_event, make_failures


def test_below_threshold_no_alert():
    events = make_failures(4, ip="192.0.2.1", step=10)  # esik 5, 4 deneme
    assert detect_brute_force(events, window=300, threshold=5) == []


def test_at_threshold_triggers():
    events = make_failures(5, ip="192.0.2.1", step=10)
    alerts = detect_brute_force(events, window=300, threshold=5)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "brute_force"
    assert a.source_ip == "192.0.2.1"
    assert a.count == 5


def test_spread_beyond_window_no_alert():
    # 6 deneme ama her biri 100s arayla -> hicbir 300s'lik pencerede 5 birikmez.
    events = make_failures(6, ip="192.0.2.1", step=100)
    assert detect_brute_force(events, window=300, threshold=5) == []


def test_severity_escalates_with_volume():
    # threshold=3: >=9 HIGH (3x), >=6 MEDIUM (2x), >=3 LOW
    low = detect_brute_force(make_failures(3, step=5), window=300, threshold=3)[0]
    med = detect_brute_force(make_failures(6, step=5), window=300, threshold=3)[0]
    high = detect_brute_force(make_failures(9, step=5), window=300, threshold=3)[0]
    assert low.severity == Severity.LOW
    assert med.severity == Severity.MEDIUM
    assert high.severity == Severity.HIGH


def test_invalid_user_not_counted_as_brute_force():
    # Sadece INVALID_USER olaylari -> brute_force tetiklenmez.
    events = [make_event(offset=i * 5, event_type=EventType.INVALID_USER, ip="192.0.2.1") for i in range(8)]
    assert detect_brute_force(events, window=300, threshold=5) == []


def test_separate_ips_counted_independently():
    events = make_failures(5, ip="192.0.2.1", step=5) + make_failures(3, ip="192.0.2.2", step=5)
    alerts = detect_brute_force(events, window=300, threshold=5)
    assert len(alerts) == 1          # sadece .1 esigi asar
    assert alerts[0].source_ip == "192.0.2.1"


def test_evidence_capped_at_ten():
    events = make_failures(20, ip="192.0.2.1", step=2)
    alert = detect_brute_force(events, window=300, threshold=5)[0]
    assert len(alert.evidence) <= 10


# --------------------------------------------------------------------------- #
# GECERSIZ YAPILANDIRMA — sessiz cop yerine net hata
# --------------------------------------------------------------------------- #
import pytest


def test_negative_window_raises_instead_of_crashing():
    """window<0 eskiden two-pointer'i tasirip IndexError veriyordu."""
    with pytest.raises(ValueError, match="window"):
        detect_brute_force(make_failures(6), window=-1, threshold=5)


def test_threshold_below_one_raises():
    """threshold<=0 eskiden TEK olayla bile 'high' alarm uretiyordu."""
    with pytest.raises(ValueError, match="threshold"):
        detect_brute_force(make_failures(6), window=300, threshold=0)


def test_window_zero_only_groups_same_second_events():
    """window=0 gecerlidir: yalnizca AYNI saniyedeki olaylar birlikte sayilir."""
    same_second = [make_event(offset=0, ip="192.0.2.1") for _ in range(5)]
    assert len(detect_brute_force(same_second, window=0, threshold=5)) == 1
    spread = make_failures(5, ip="192.0.2.1", step=1)
    assert detect_brute_force(spread, window=0, threshold=5) == []


# --- karakterizasyon: ortak kayan pencere davranisi (refactor oncesi sabitlendi) --- #

def test_unordered_input_same_result():
    ordered = make_failures(6, ip="192.0.2.1", step=10)
    shuffled = [ordered[i] for i in (3, 0, 5, 1, 4, 2)]
    a, b = detect_brute_force(ordered)[0], detect_brute_force(shuffled)[0]
    assert (a.count, a.severity, a.time_window, a.description, a.evidence) == \
           (b.count, b.severity, b.time_window, b.description, b.evidence)


def test_exact_window_boundary_is_inclusive():
    # ilk ile son arasi tam 'window' saniye -> ayni pencere.
    events = make_failures(5, ip="192.0.2.1", step=75)          # 0..300
    alerts = detect_brute_force(events, window=300, threshold=5)
    assert len(alerts) == 1 and alerts[0].count == 5


def test_window_plus_one_is_outside():
    events = make_failures(4, ip="192.0.2.1", step=75) + [make_event(offset=301, ip="192.0.2.1")]
    assert detect_brute_force(events, window=300, threshold=5) == []


def test_evidence_comes_from_densest_window_chronologically():
    sparse = [make_event(offset=o, ip="192.0.2.1") for o in (0, 1000)]
    dense = make_failures(5, ip="192.0.2.1", step=5, start=2000)
    alerts = detect_brute_force(list(reversed(sparse + dense)), window=300, threshold=5)
    assert alerts[0].count == 5
    assert alerts[0].evidence == [e.raw_line for e in dense]


def test_one_alert_per_ip_even_with_many_windows():
    events = make_failures(5, ip="192.0.2.1", step=5) + make_failures(6, ip="192.0.2.1", step=5, start=3600)
    alerts = detect_brute_force(events, window=300, threshold=5)
    assert len(alerts) == 1
    assert alerts[0].count == 6                                  # en yogun pencere


def test_equal_density_tie_keeps_earliest_window():
    # Iki ayri pencere ayni yogunlukta (3'er olay): ILK bulunan kazanir.
    first = make_failures(3, ip="192.0.2.1", step=5)            # 0, 5, 10
    second = make_failures(3, ip="192.0.2.1", step=5, start=100)  # 100, 105, 110
    alerts = detect_brute_force(second + first, window=10, threshold=3)
    assert alerts[0].evidence == [e.raw_line for e in first]
    assert alerts[0].time_window == "05:00:00-05:00:10 (10s)"
