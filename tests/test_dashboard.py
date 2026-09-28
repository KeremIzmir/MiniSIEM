"""
test_dashboard.py — Flask panosunun rotalari, fabrikasi ve CLI kabugu.

NEDEN AYRI BIR DOSYA: Pano, projenin CLI kadar buyuk ikinci arayuzu ama tek satiri
bile test edilmiyordu. create_app(store) bilincli olarak store'u DISARDAN aliyor
(application factory) — tam da bunun icin: gercek dosya okumadan, kucuk ve
deterministik bir store ile rotalari calistirabiliyoruz.

Flask kurulu degilse tum dosya atlanir; cekirdek (parser/detection/storage/cli)
stdlib-only kalmali, pano testleri onu bagimli hale getirmemeli.
"""

import json
from pathlib import Path

import pytest

flask = pytest.importorskip("flask", reason="pano testleri icin flask gerekir")

from parser.events import EventType
from detection.alert import Alert, Severity
from storage.store import EventStore
from dashboard.app import build_store, create_app, build_arg_parser
from conftest import make_event

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_auth.log"


@pytest.fixture
def store() -> EventStore:
    """Rotalari beslemek icin kucuk ama her alani dolu bir store."""
    s = EventStore()
    s.add_events([
        make_event(offset=0, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.1"),
        make_event(offset=20, event_type=EventType.FAILED_PASSWORD, ip="192.0.2.1"),
        make_event(offset=65, event_type=EventType.INVALID_USER, ip="192.0.2.2", user="oracle"),
        make_event(offset=90, event_type=EventType.ACCEPTED_LOGIN, ip="198.51.100.5", user="alice"),
    ])
    s.unparsed_count = 3
    s.add_alert(Alert(
        rule_name="brute_force", severity=Severity.HIGH, source_ip="192.0.2.1",
        count=9, time_window="05:00:00-05:00:20 (20s)",
        description="test alarmi", evidence=["ham satir 1", "ham satir 2"],
    ))
    return s


@pytest.fixture
def client(store):
    app = create_app(store)
    app.config.update(TESTING=True)
    return app.test_client()


# ------------------------------- rotalar ---------------------------------- #
def test_index_renders_html(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Ozet kartlari, alarm ve IP tablosu sayfada gorunmeli.
    assert "Mini SIEM" in body
    assert "brute_force" in body
    assert "192.0.2.1" in body
    assert "test alarmi" in body


def test_index_shows_unparsed_card_only_when_nonzero(store):
    """summary.unparsed 0 ise 'Parse edilemeyen' karti hic basilmamali."""
    with_unparsed = create_app(store).test_client().get("/").get_data(as_text=True)
    assert "Parse edilemeyen" in with_unparsed

    store.unparsed_count = 0
    without = create_app(store).test_client().get("/").get_data(as_text=True)
    assert "Parse edilemeyen" not in without


def test_index_empty_store_shows_placeholders():
    """Bos store'da sablon cokmemeli; 'veri yok' metinlerini gostermeli."""
    r = create_app(EventStore()).test_client().get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Alarm yok" in body
    assert "Veri yok" in body


def test_api_summary(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    data = r.get_json()
    assert data["toplam_olay"] == 4
    assert data["basarisiz_giris"] == 3
    assert data["benzersiz_ip"] == 3
    assert data["alarm_sayisi"] == 1
    assert data["unparsed"] == 3


def test_api_alerts(client):
    data = client.get("/api/alerts").get_json()
    assert len(data) == 1
    assert data[0]["rule_name"] == "brute_force"
    assert data[0]["severity"] == "high"        # to_dict() -> .value, enum degil
    assert data[0]["evidence"] == ["ham satir 1", "ham satir 2"]
    # jsonify ciktisi gercekten JSON-serialize edilebilir olmali.
    json.dumps(data)


def test_api_timeline_shape(client):
    data = client.get("/api/timeline").get_json()
    # [(dakika, sayi)] -> [{"t":..., "count":...}] donusumu
    assert data == [{"t": "2026-06-01 05:00", "count": 2},
                    {"t": "2026-06-01 05:01", "count": 1}]


def test_unknown_route_404(client):
    assert client.get("/yok-boyle-bir-rota").status_code == 404


def test_log_injection_is_escaped_in_html():
    """
    Ham log satiri HTML icerirse sayfaya ETIKET olarak degil METIN olarak girmeli.
    (Jinja2 otomatik escape — pano saldirgan kontrolundeki veriyi gosteriyor.)
    """
    s = EventStore()
    s.add_alert(Alert(
        rule_name="brute_force", severity=Severity.LOW, source_ip="192.0.2.1",
        count=5, time_window=None, description="x",
        evidence=["<script>alert(1)</script>"],
    ))
    body = create_app(s).test_client().get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


# ----------------------------- build_store -------------------------------- #
def test_build_store_end_to_end():
    """build_store, CLI ile AYNI akisi kurar: parse -> store -> kurallar."""
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    s = build_store(str(SAMPLE_LOG))
    summary = s.summary()
    assert summary["toplam_olay"] == 36
    assert summary["unparsed"] == 1
    assert summary["alarm_sayisi"] == len(s.alerts) > 0


def test_build_store_allowlist_filters():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    normal = build_store(str(SAMPLE_LOG))
    allowed = build_store(str(SAMPLE_LOG), allowlist=["192.0.2.10"])
    ips_normal = {a["source_ip"] for a in normal.alerts}
    ips_allowed = {a["source_ip"] for a in allowed.alerts}
    assert "192.0.2.10" in ips_normal
    assert "192.0.2.10" not in ips_allowed
    # Allowlist yalnizca TESPITI filtreler; olaylar depoda kalmali.
    assert normal.summary()["toplam_olay"] == allowed.summary()["toplam_olay"]


def test_build_store_passes_rule_parameters():
    """
    Kural parametreleri gercekten kurallara ULASMALI (sadece imzada durmamali).
    min_fails=99 ile fail_then_success asla tetiklenemez.
    """
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    default = build_store(str(SAMPLE_LOG))
    tuned = build_store(str(SAMPLE_LOG), min_fails=99)
    assert any(a["rule_name"] == "fail_then_success" for a in default.alerts)
    assert not any(a["rule_name"] == "fail_then_success" for a in tuned.alerts)


def test_build_store_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        build_store("yok_boyle_bir_dosya.log")


# --------------------------- arguman ayristirici --------------------------- #
def test_arg_parser_defaults():
    args = build_arg_parser().parse_args(["auth.log"])
    assert args.logfile == "auth.log"
    assert args.host == "127.0.0.1"     # disa acik 0.0.0.0 BILINCLI secim olmali
    assert args.port == 5000
    assert args.debug is False          # guvenlik: debug varsayilan KAPALI
    assert args.window == 300
    assert args.threshold == 5
    assert args.enum_threshold == 5
    assert args.min_fails == 3
    assert args.success_window == 600
    assert args.anomaly_k == 2.0
    assert args.anomaly_min_volume == 5


def test_arg_parser_accepts_overrides():
    args = build_arg_parser().parse_args([
        "auth.log", "--host", "0.0.0.0", "--port", "8080", "--debug",
        "--min-fails", "7", "--anomaly-k", "3.5", "--allow", "10.0.0.1", "--allow", "10.0.0.2",
    ])
    assert args.host == "0.0.0.0"
    assert args.port == 8080
    assert args.debug is True
    assert args.min_fails == 7
    assert args.anomaly_k == 3.5
    assert args.allow == ["10.0.0.1", "10.0.0.2"]


# ------------------------------ sudo_brute_force ----------------------------- #
def test_arg_parser_sudo_defaults_and_overrides():
    args = build_arg_parser().parse_args(["auth.log"])
    assert (args.sudo_window, args.sudo_threshold) == (300, 3)
    args = build_arg_parser().parse_args(["auth.log", "--sudo-window", "60", "--sudo-threshold", "5"])
    assert (args.sudo_window, args.sudo_threshold) == (60, 5)


def _sudo_rules(store):
    return [a for a in store.alerts if a["rule_name"] == "sudo_brute_force"]


def test_build_store_passes_sudo_parameters():
    # Ornekte 2 sudo basarisizligi (5 sn arayla): varsayilan esik 3 ile alarm yok.
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    assert _sudo_rules(build_store(str(SAMPLE_LOG))) == []
    tuned = build_store(str(SAMPLE_LOG), sudo_threshold=2)
    assert len(_sudo_rules(tuned)) == 1
    assert tuned.summary()["alarm_sayisi"] == 7
    assert _sudo_rules(build_store(str(SAMPLE_LOG), sudo_threshold=2, sudo_window=4)) == []


def test_build_store_rejects_invalid_sudo_config():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    with pytest.raises(ValueError):
        build_store(str(SAMPLE_LOG), sudo_threshold=0)


@pytest.mark.parametrize("flag,value", [("--sudo-threshold", "0"), ("--sudo-window", "-1")])
def test_main_invalid_sudo_config_exits_2(monkeypatch, capsys, flag, value):
    # main() gecersiz ayarda sunucuyu BASLATMADAN kullanim hatasiyla cikmali.
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    from dashboard import app as app_module
    monkeypatch.setattr("sys.argv", ["mini-siem-dashboard", str(SAMPLE_LOG), flag, value])
    with pytest.raises(SystemExit) as exc:
        app_module.main()
    assert exc.value.code == 2
    assert "gecersiz tespit ayari" in capsys.readouterr().err
