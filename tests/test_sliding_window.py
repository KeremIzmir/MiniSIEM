"""
test_sliding_window.py — ortak "en yogun kayan pencere" secicisinin sozlesmesi.

Yardimci yalnizca pencere secer: olay turunu, gruplamayi, esigi, severity'yi veya
Alert'i bilmez. Bu testler de yalnizca pencere secimini dogrular.
"""

from detection.sliding_window import densest_window
from conftest import make_event


def at(*offsets):
    """Verilen saniye ofsetlerinde olaylar (kimlikleri karsilastirmak icin sirali)."""
    return [make_event(offset=o) for o in offsets]


def test_empty_input_returns_empty():
    assert densest_window([], window=300) == []


def test_single_event_returns_that_event():
    events = at(0)
    assert densest_window(events, window=300) == events


def test_unordered_input_returns_chronological_window():
    events = at(0, 5, 10)
    result = densest_window([events[2], events[0], events[1]], window=300)
    assert result == events


def test_all_events_inside_window():
    events = at(0, 100, 200)
    assert densest_window(events, window=300) == events


def test_exact_boundary_is_inclusive():
    # fark == window -> ayni pencere
    events = at(0, 150, 300)
    assert densest_window(events, window=300) == events


def test_just_outside_boundary_is_excluded():
    events = at(0, 150, 301)
    result = densest_window(events, window=300)
    assert result == events[:2]            # en yogun: ilk iki (esitlikte ilk kazanir)


def test_densest_sub_window_is_selected():
    sparse = at(0, 1000)
    dense = at(2000, 2005, 2010, 2015)
    assert densest_window(sparse + dense, window=300) == dense


def test_equal_density_tie_keeps_first_window():
    # Iki ayri pencere 3'er olay: sol-sag taramada ILK maksimum kazanir ('>' ile).
    first, second = at(0, 5, 10), at(100, 105, 110)
    assert densest_window(second + first, window=10) == first


def test_duplicate_timestamps_counted_individually():
    events = at(0, 0, 0, 500)
    assert densest_window(events, window=10) == events[:3]


def test_zero_second_window_groups_only_identical_timestamps():
    same = at(7, 7)
    other = at(0, 8)
    assert densest_window(other + same, window=0) == same


def test_zero_second_window_distinct_timestamps_do_not_combine():
    events = at(0, 1, 2)
    assert densest_window(events, window=0) == events[:1]


def test_equal_timestamps_keep_input_order():
    # Kararli (stable) siralama: ayni zaman damgali olaylar girdi sirasini korur.
    a, b = make_event(offset=0, ip="192.0.2.1"), make_event(offset=0, ip="192.0.2.2")
    assert densest_window([b, a], window=0) == [b, a]


def test_input_list_is_not_mutated():
    events = at(10, 0, 5)
    snapshot = list(events)
    densest_window(events, window=300)
    assert events == snapshot
