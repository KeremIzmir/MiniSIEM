"""
test_detection_config.py — DetectionConfig, config tabanli motor yolu ve eski API uyumlulugu.

NEDEN: Tespit ayarlari tek bir kanonik modelde (DetectionConfig) toplandi. Eski
run_detections(...) imzasi bugunku 14 ayarla DONDURULMUS bir uyumluluk adaptoru olarak
kalir; burada iki yolun birebir ayni alarmlari ve ayni hatalari urettigi sabitlenir.
"""

import dataclasses
import inspect
from pathlib import Path
from typing import List, Optional

import pytest

from parser.auth_parser import parse_file
from parser.events import Event, EventType
from detection.alert import Alert
from detection.config import DEFAULT_DETECTION_CONFIG, DetectionConfig
from detection.engine import run_detections, run_detections_with_config
from conftest import make_event

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_auth.log"

FIELDS = [
    "window", "threshold", "enum_threshold", "allowlist", "min_fails", "success_window",
    "anomaly_k", "anomaly_min_volume", "sudo_window", "sudo_threshold", "su_window",
    "su_threshold", "su_success_min_fails", "su_success_window",
]
DEFAULTS = [300, 5, 5, None, 3, 600, 2.0, 5, 300, 3, 300, 3, 3, 600]


# ------------------------------ config modeli ------------------------------- #
def test_field_order_matches_engine_signature():
    assert [f.name for f in dataclasses.fields(DetectionConfig)] == FIELDS


def test_defaults_exact():
    c = DetectionConfig()
    assert [getattr(c, name) for name in FIELDS] == DEFAULTS
    assert isinstance(c.anomaly_k, float)


def test_shared_default_object_equals_fresh_config():
    assert DEFAULT_DETECTION_CONFIG == DetectionConfig()


def test_config_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_DETECTION_CONFIG.threshold = 9


@pytest.mark.parametrize("allow", [None, (), ("B", "A", "B")])
def test_allowlist_tuple_retained_exactly(allow):
    assert DetectionConfig(allowlist=allow).allowlist == allow
    assert DetectionConfig(allowlist=None).allowlist is None


def test_config_does_not_validate():
    # Dogrulama kurallarda kalir: gecersiz deger config kurarken HATA VERMEZ.
    assert DetectionConfig(window=-1, threshold=0, anomaly_k=-5.0).window == -1


# ------------------------------ ortak korpus -------------------------------- #
def _su(offset, kind=EventType.SU_FAILURE, actor="alice", target="root"):
    e = make_event(offset=offset, event_type=kind, ip=None, user=target, process="su")
    e.port = None
    e.actor_username = actor
    return e


def _sudo(offset, user="bob"):
    e = make_event(offset=offset, event_type=EventType.SUDO_FAILURE, ip=None, user=user, process="sudo")
    e.port = None
    e.actor_username = user
    return e


def _corpus() -> List[Event]:
    events, _ = parse_file(str(SAMPLE_LOG))
    local = [_sudo(i * 20) for i in range(4)]
    local += [_su(i * 30) for i in range(4)] + [_su(130, kind=EventType.SU_SUCCESS)]
    return events + local


def _keys(alerts: List[Alert]):
    return [(a.rule_name, a.severity, a.source_ip, a.count, a.time_window, a.description,
             tuple(a.evidence)) for a in alerts]


def _legacy_kwargs(overrides: dict) -> dict:
    kw = dict(overrides)
    if kw.get("allowlist") is not None:
        kw["allowlist"] = list(kw["allowlist"])      # eski API liste alir
    return kw


# -------------------------- motor: iki yol birebir -------------------------- #
def test_default_config_matches_legacy_defaults():
    events = _corpus()
    assert _keys(run_detections(events)) == _keys(run_detections_with_config(events, DetectionConfig()))
    assert len(run_detections(events)) > 0


OVERRIDES = [
    {"window": 30}, {"window": 900},
    {"threshold": 3}, {"threshold": 9},
    {"enum_threshold": 3}, {"enum_threshold": 50},
    {"allowlist": ("192.0.2.20",)}, {"allowlist": ("192.0.2.20", "192.0.2.10", "192.0.2.20")},
    {"allowlist": ()},
    {"min_fails": 1}, {"min_fails": 99},
    {"success_window": 10}, {"success_window": 3600},
    {"anomaly_k": 0.5}, {"anomaly_k": 10.0},
    {"anomaly_min_volume": 1}, {"anomaly_min_volume": 100},
    {"sudo_window": 10}, {"sudo_window": 3600},
    {"sudo_threshold": 1}, {"sudo_threshold": 9},
    {"su_window": 10}, {"su_window": 3600},
    {"su_threshold": 1}, {"su_threshold": 9},
    {"su_success_min_fails": 1}, {"su_success_min_fails": 9},
    {"su_success_window": 10}, {"su_success_window": 3600},
    {"threshold": 3, "sudo_threshold": 2, "su_threshold": 2, "allowlist": ("192.0.2.30",),
     "anomaly_k": 1.0, "su_success_min_fails": 2},
]


@pytest.mark.parametrize("overrides", OVERRIDES, ids=lambda o: ",".join(o))
def test_every_setting_legacy_equals_config_native(overrides):
    events = _corpus()
    legacy = run_detections(events, **_legacy_kwargs(overrides))
    native = run_detections_with_config(events, DetectionConfig(**overrides))
    assert _keys(legacy) == _keys(native)


def test_every_field_is_exercised_by_overrides():
    assert {name for o in OVERRIDES for name in o} == set(FIELDS)


INVALID = [
    {"window": -1}, {"threshold": 0}, {"enum_threshold": 0}, {"min_fails": 0},
    {"success_window": -1}, {"sudo_window": -1}, {"sudo_threshold": 0}, {"su_window": -1},
    {"su_threshold": 0}, {"su_success_min_fails": 0}, {"su_success_window": -1},
    {"window": -1, "sudo_window": -1},                  # ilk hata: brute_force
    {"su_threshold": 0, "enum_threshold": 0},           # ilk hata: enumeration
    {"su_success_window": -1, "sudo_threshold": 0},     # ilk hata: sudo_brute_force
]


def _error(fn):
    with pytest.raises(ValueError) as info:
        fn()
    return type(info.value), str(info.value)


@pytest.mark.parametrize("events", [[], None], ids=["empty", "corpus"])
@pytest.mark.parametrize("overrides", INVALID, ids=lambda o: ",".join(o))
def test_invalid_config_same_error_on_both_paths(overrides, events):
    events = _corpus() if events is None else events
    legacy = _error(lambda: run_detections(events, **overrides))
    native = _error(lambda: run_detections_with_config(events, DetectionConfig(**overrides)))
    assert legacy == native


def test_anomaly_settings_remain_unvalidated():
    events = _corpus()
    run_detections_with_config(events, DetectionConfig(anomaly_k=-1.0, anomaly_min_volume=-1))


# --------------------- eski imza: dondurulmus uyumluluk yuzeyi ------------------- #
def test_run_detections_signature_frozen():
    params = inspect.signature(run_detections).parameters
    assert list(params) == ["events"] + FIELDS
    assert [params[name].default for name in FIELDS] == DEFAULTS
    assert params["events"].default is inspect.Parameter.empty
    assert all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params.values())
    assert params["allowlist"].annotation == Optional[List[str]]
    assert params["anomaly_k"].annotation is float
    assert params["window"].annotation is int


def test_run_detections_positional_call_still_works():
    events = _corpus()
    positional = run_detections(events, 300, 5, 5, None, 3, 600, 2.0, 5, 300, 3, 300, 3, 3, 600)
    assert _keys(positional) == _keys(run_detections(events))


def test_legacy_allowlist_list_becomes_tuple_in_config_semantics():
    # Eski API liste/tekrar kabul eder; sonuc tuple config ile ayni (set tabanli filtre).
    events = _corpus()
    legacy = run_detections(events, allowlist=["192.0.2.20", "192.0.2.20"])
    native = run_detections_with_config(events, DetectionConfig(allowlist=("192.0.2.20",)))
    assert _keys(legacy) == _keys(native)
