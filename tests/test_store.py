"""
test_store.py — EventStore: sayim, gruplama ve JSON kalicilik.
"""

import json

from parser.events import EventType
from detection.alert import Alert, Severity
from storage.store import EventStore
from conftest import make_event


def _store_with_mixed_events() -> EventStore:
    store = EventStore()
    store.add_events([
        make_event(offset=0, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.1"),
        make_event(offset=30, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.1"),
        make_event(offset=70, event_type=EventType.INVALID_USER, ip="192.0.2.2"),
        make_event(offset=90, event_type=EventType.ACCEPTED_LOGIN, ip="198.51.100.5"),
    ])
    return store


def test_summary_counts():
    store = _store_with_mixed_events()
    store.unparsed_count = 2
    s = store.summary()
    assert s["toplam_olay"] == 4
    assert s["basarisiz_giris"] == 3      # 2 FAILED + 1 INVALID_USER
    assert s["benzersiz_ip"] == 3
    assert s["alarm_sayisi"] == 0
    assert s["unparsed"] == 2


def test_top_ips_ordering():
    store = _store_with_mixed_events()
    top = store.top_ips(limit=10)
    assert top[0] == ("192.0.2.1", 2)     # en cok olay ureten basta
    assert dict(top)["192.0.2.2"] == 1


def test_unique_ips_ignores_none():
    store = EventStore()
    store.add_events([
        make_event(ip="192.0.2.1"),
        make_event(event_type=EventType.SUDO_FAILURE, ip=None, user="bob"),
    ])
    assert store.unique_ips() == {"192.0.2.1"}


def test_failed_per_minute_buckets_by_minute():
    store = EventStore()
    # Ayni dakikada 2, sonraki dakikada 1 basarisizlik.
    store.add_events([
        make_event(offset=0, event_type=EventType.FAILED_PASSWORD),
        make_event(offset=20, event_type=EventType.FAILED_PASSWORD),
        make_event(offset=65, event_type=EventType.FAILED_PASSWORD),
    ])
    series = store.failed_per_minute()
    counts = [c for _, c in series]
    assert counts == [2, 1]
    # Zamana gore sirali olmali (label artarak).
    assert series == sorted(series)


def test_add_alert_stores_dict_form():
    store = EventStore()
    alert = Alert(rule_name="brute_force", severity=Severity.HIGH, source_ip="192.0.2.1",
                  count=9, time_window="05:00-05:01", description="test", evidence=["x"])
    store.add_alert(alert)
    assert store.alerts[0]["severity"] == "high"   # to_dict() -> .value
    assert store.alerts[0]["rule_name"] == "brute_force"


def test_to_json_roundtrip(tmp_path):
    store = _store_with_mixed_events()
    path = tmp_path / "rapor.json"
    text = store.to_json(str(path))
    # Hem string dondurur hem dosyaya yazar; ikisi de gecerli JSON.
    data = json.loads(text)
    assert data["summary"]["toplam_olay"] == 4
    assert len(data["events"]) == 4
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == data


def test_add_event_single():
    """add_event: tekil ekleme yolu (SQLite'a gecince degisecek tek nokta)."""
    store = EventStore()
    store.add_event(make_event(ip="192.0.2.1"))
    assert len(store.events) == 1
    assert store.events[0].source_ip == "192.0.2.1"


def test_add_alert_accepts_plain_dict():
    """
    add_alert, to_dict()'i olmayan duz dict'i de kabul eder — storage'in
    detection.alert modulune BAGIMLI OLMAMASI (gevsek baglilik) bunu gerektirir.
    """
    store = EventStore()
    store.add_alert({"rule_name": "custom", "severity": "low"})
    assert store.alerts[0]["rule_name"] == "custom"


def test_to_json_without_path_returns_string_only(tmp_path):
    """path=None: string dondurur, hicbir dosya yazmaz."""
    store = _store_with_mixed_events()
    text = store.to_json()
    data = json.loads(text)
    assert data["summary"]["toplam_olay"] == 4
    assert list(tmp_path.iterdir()) == []      # yan etki yok


def test_to_json_is_utf8_readable():
    """ensure_ascii=False: Turkce karakterler kacisli degil okunur kalmali."""
    store = EventStore()
    store.add_alert({"description": "basarisiz giris denemesi - sunucu cokusu"})
    assert "basarisiz" in store.to_json()



# --- sudo parola-denemesi ozeti: genel basarisizlik sayaclarina girmez ------------ #

def _sudo_fail_and_summary():
    fail = make_event(0, event_type=EventType.SUDO_FAILURE, ip=None, user="alice", process="sudo")
    summary = make_event(1, event_type=EventType.SUDO_INCORRECT_PASSWORD_SUMMARY, ip=None,
                         user="alice", process="sudo")
    summary.actor_username = "alice"
    summary.attempt_count = 3
    return fail, summary


def test_summary_counted_as_event_but_not_failure():
    store = EventStore()
    store.add_events(list(_sudo_fail_and_summary()))
    s = store.summary()
    assert s["toplam_olay"] == 2
    assert s["basarisiz_giris"] == 1                 # yalnizca birincil PAM hatasi
    assert s["benzersiz_ip"] == 0
    assert [e.event_type for e in store.failed_events()] == [EventType.SUDO_FAILURE]
    assert sum(n for _, n in store.failed_per_minute()) == 1


def test_summary_json_includes_attempt_count():
    store = EventStore()
    store.add_events(list(_sudo_fail_and_summary()))
    data = json.loads(store.to_json())
    by_type = {e["event_type"]: e for e in data["events"]}
    assert by_type["SUDO_INCORRECT_PASSWORD_SUMMARY"]["attempt_count"] == 3
    assert by_type["SUDO_FAILURE"]["attempt_count"] is None



# --- kanonik basarisiz_kimlik_dogrulama + legacy basarisiz_giris alias'i ------- #
# Kanonik anahtar Event.is_failure taksonomisini sayar; eski anahtar geriye uyumluluk
# icin AYNI degerle uretilmeye devam eder (deprecated alias, runtime uyarisi yok).

_PRIMARY_FAILURES = [EventType.FAILED_PASSWORD, EventType.INVALID_USER, EventType.SUDO_FAILURE,
                     EventType.SU_FAILURE, EventType.AUTH_FAILURE]
_NON_FAILURES = [EventType.ACCEPTED_LOGIN, EventType.SU_SUCCESS,
                 EventType.SUDO_INCORRECT_PASSWORD_SUMMARY, EventType.UNKNOWN]


def test_summary_emits_canonical_and_legacy_failure_keys():
    s = _store_with_mixed_events().summary()
    assert "basarisiz_kimlik_dogrulama" in s
    assert "basarisiz_giris" in s
    assert s["basarisiz_kimlik_dogrulama"] == s["basarisiz_giris"] == 3


def test_failure_keys_zero_without_failures():
    s = EventStore().summary()
    assert s["basarisiz_kimlik_dogrulama"] == s["basarisiz_giris"] == 0


def test_failure_keys_count_every_primary_failure_type():
    store = EventStore()
    store.add_events([make_event(offset=i, event_type=t) for i, t in enumerate(_PRIMARY_FAILURES)])
    s = store.summary()
    assert s["basarisiz_kimlik_dogrulama"] == s["basarisiz_giris"] == 5


def test_failure_keys_exclude_successes_summaries_and_unknown():
    store = EventStore()
    store.add_events([make_event(offset=0, event_type=EventType.SUDO_FAILURE)]
                     + [make_event(offset=i + 1, event_type=t) for i, t in enumerate(_NON_FAILURES)])
    s = store.summary()
    assert s["toplam_olay"] == 5
    assert s["basarisiz_kimlik_dogrulama"] == s["basarisiz_giris"] == 1


def test_failure_count_is_computed_once_for_both_keys(monkeypatch):
    # Iki anahtar tek hesaplamadan gelmeli; bagimsiz hesaplama drift'e kapi acar.
    store = _store_with_mixed_events()
    calls = []
    original = store.failed_events

    def spy():
        calls.append(1)
        return original()

    monkeypatch.setattr(store, "failed_events", spy)
    store.summary()
    assert len(calls) == 1


def test_json_export_emits_both_failure_keys():
    store = _store_with_mixed_events()
    data = json.loads(store.to_json())
    summary = data["summary"]
    assert summary["basarisiz_kimlik_dogrulama"] == 3
    assert summary["basarisiz_giris"] == 3                          # eski tuketici calismaya devam eder
    assert summary["basarisiz_kimlik_dogrulama"] == summary["basarisiz_giris"]
    assert len(data["events"]) == 4 and data["alerts"] == []
