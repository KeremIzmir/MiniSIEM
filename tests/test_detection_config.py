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


# ------------------- ortak komut satiri secenekleri (CLI + pano) -------------------- #
import argparse

import cli
from detection.options import add_detection_arguments, detection_config_from_namespace

flask = pytest.importorskip("flask", reason="pano parser'i icin flask gerekir")
from dashboard.app import build_arg_parser, build_store, build_store_with_config  # noqa: E402

# Bugunku sozlesme: (option, dest, type, default, action sinifi, metavar) — sirasiyla.
DETECTION_OPTIONS = [
    ("--window", "window", int, 300, argparse._StoreAction, None),
    ("--threshold", "threshold", int, 5, argparse._StoreAction, None),
    ("--enum-threshold", "enum_threshold", int, 5, argparse._StoreAction, None),
    ("--min-fails", "min_fails", int, 3, argparse._StoreAction, None),
    ("--success-window", "success_window", int, 600, argparse._StoreAction, None),
    ("--anomaly-k", "anomaly_k", float, 2.0, argparse._StoreAction, None),
    ("--anomaly-min-volume", "anomaly_min_volume", int, 5, argparse._StoreAction, None),
    ("--sudo-window", "sudo_window", int, 300, argparse._StoreAction, None),
    ("--sudo-threshold", "sudo_threshold", int, 3, argparse._StoreAction, None),
    ("--su-window", "su_window", int, 300, argparse._StoreAction, None),
    ("--su-threshold", "su_threshold", int, 3, argparse._StoreAction, None),
    ("--su-success-min-fails", "su_success_min_fails", int, 3, argparse._StoreAction, None),
    ("--su-success-window", "su_success_window", int, 600, argparse._StoreAction, None),
    ("--allow", "allow", None, None, argparse._AppendAction, "IP"),
]
DETECTION_FLAGS = [o[0] for o in DETECTION_OPTIONS]


def _optionals(parser):
    return [a for a in parser._actions if a.option_strings and a.dest != "help"]


def _detection_actions(parser):
    return [a for a in _optionals(parser) if a.option_strings[0] in DETECTION_FLAGS]


def _describe(action):
    return (action.option_strings[0], action.dest, action.type, action.default, type(action),
            action.metavar)


@pytest.mark.parametrize("make", [cli.build_parser, build_arg_parser, ], ids=["cli", "dashboard"])
def test_detection_options_contract(make):
    actions = _detection_actions(make())
    assert [_describe(a) for a in actions] == DETECTION_OPTIONS
    assert all(a.option_strings == [a.option_strings[0]] for a in actions)
    assert all(a.nargs is None and a.const is None for a in actions)


def test_cli_and_dashboard_detection_actions_identical_including_help():
    c, d = _detection_actions(cli.build_parser()), _detection_actions(build_arg_parser())
    assert [(_describe(a), a.nargs, a.const, a.help) for a in c] == \
           [(_describe(a), a.nargs, a.const, a.help) for a in d]


def test_cli_option_order_preserved():
    flags = [a.option_strings[0] for a in _optionals(cli.build_parser())]
    assert flags == ["--json"] + DETECTION_FLAGS + ["--quiet", "--no-color", "--version"]


def test_dashboard_option_order_preserved():
    flags = [a.option_strings[0] for a in _optionals(build_arg_parser())]
    assert flags == ["--host", "--port"] + DETECTION_FLAGS + ["--debug", "--version"]


def test_shared_helper_adds_only_detection_options():
    p = argparse.ArgumentParser()
    add_detection_arguments(p)
    assert [a.option_strings[0] for a in _optionals(p)] == DETECTION_FLAGS


def test_help_defaults_come_from_config():
    helps = {a.dest: a.help for a in _detection_actions(cli.build_parser())}
    assert helps["window"].endswith(f"Varsayilan {DEFAULT_DETECTION_CONFIG.window}.")
    assert helps["anomaly_k"].endswith(f"Varsayilan {DEFAULT_DETECTION_CONFIG.anomaly_k}.")


@pytest.mark.parametrize("make", [cli.build_parser, build_arg_parser], ids=["cli", "dashboard"])
def test_namespace_defaults_map_to_default_config(make):
    args = make().parse_args(["auth.log"])
    assert args.allow is None
    assert detection_config_from_namespace(args) == DEFAULT_DETECTION_CONFIG


@pytest.mark.parametrize("make", [cli.build_parser, build_arg_parser], ids=["cli", "dashboard"])
def test_namespace_all_fields_mapped_explicitly(make):
    argv = ["auth.log", "--window", "11", "--threshold", "12", "--enum-threshold", "13",
            "--min-fails", "14", "--success-window", "15", "--anomaly-k", "1.5",
            "--anomaly-min-volume", "16", "--sudo-window", "17", "--sudo-threshold", "18",
            "--su-window", "19", "--su-threshold", "20", "--su-success-min-fails", "21",
            "--su-success-window", "22", "--allow", "192.0.2.1"]
    assert detection_config_from_namespace(make().parse_args(argv)) == DetectionConfig(
        window=11, threshold=12, enum_threshold=13, allowlist=("192.0.2.1",), min_fails=14,
        success_window=15, anomaly_k=1.5, anomaly_min_volume=16, sudo_window=17,
        sudo_threshold=18, su_window=19, su_threshold=20, su_success_min_fails=21,
        su_success_window=22)


@pytest.mark.parametrize("make", [cli.build_parser, build_arg_parser], ids=["cli", "dashboard"])
def test_repeated_allow_keeps_order_and_duplicates(make):
    args = make().parse_args(["auth.log", "--allow", "B", "--allow", "A", "--allow", "B"])
    assert args.allow == ["B", "A", "B"]
    assert detection_config_from_namespace(args).allowlist == ("B", "A", "B")


def _imported_modules(module) -> set:
    import ast
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module)
    return names


def test_dependency_direction():
    # config: yalnizca stdlib; options: argparse + config (motoru import ETMEZ).
    import detection.config as config_module
    import detection.options as options_module
    assert _imported_modules(config_module) == {"dataclasses", "typing"}
    assert _imported_modules(options_module) == {"argparse", "detection.config"}


# --------------------- pano: config tabanli yol + eski build_store ------------------- #
def test_build_store_signature_frozen():
    params = inspect.signature(build_store).parameters
    assert list(params) == ["logfile"] + FIELDS
    assert [params[name].default for name in FIELDS] == DEFAULTS
    assert all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params.values())


def _store_view(store):
    return (store.summary(), [e.to_dict() for e in store.events], store.alerts)


@pytest.mark.parametrize("overrides", [
    {}, {"sudo_threshold": 2}, {"su_threshold": 1, "su_window": 10},
    {"allowlist": ("192.0.2.10",)}, {"min_fails": 99}, {"threshold": 3, "anomaly_k": 1.0},
], ids=lambda o: ",".join(o) or "default")
def test_build_store_legacy_equals_config_native(overrides):
    legacy = build_store(str(SAMPLE_LOG), **_legacy_kwargs(overrides))
    native = build_store_with_config(str(SAMPLE_LOG), DetectionConfig(**overrides))
    assert _store_view(legacy) == _store_view(native)


def test_build_store_positional_call_still_works():
    positional = build_store(str(SAMPLE_LOG), 300, 5, 5, None, 3, 600, 2.0, 5, 300, 3, 300, 3, 3, 600)
    assert _store_view(positional) == _store_view(build_store(str(SAMPLE_LOG)))


def test_build_store_with_config_invalid_config_raises_rule_error():
    with pytest.raises(ValueError, match="sudo threshold en az 1 olmali: 0"):
        build_store_with_config(str(SAMPLE_LOG), DetectionConfig(sudo_threshold=0))
