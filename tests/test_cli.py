"""
test_cli.py — komut satiri arayuzunun uctan uca davranisi.

run() cikti akisini (out) ve donus kodunu disardan alir/dondurur; bu yuzden
gercek surec baslatmadan, StringIO'ya yazdirip exit kodunu dogrudan test ederiz.
"""

import io
import json
from pathlib import Path

import pytest

import cli

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_auth.log"


def _run(argv):
    """run()'i StringIO ciktisiyla calistir; (exit_code, ciktimetni) dondur."""
    buf = io.StringIO()
    code = cli.run(argv, out=buf)
    return code, buf.getvalue()


def test_build_parser_defaults():
    args = cli.build_parser().parse_args(["auth.log"])
    assert args.logfile == "auth.log"
    assert args.window == 300
    assert args.threshold == 5
    assert args.enum_threshold == 5
    assert args.allow is None
    assert args.quiet is False


def test_missing_file_returns_2():
    code, _ = _run(["yok_boyle_bir_dosya.log"])
    assert code == 2


def test_clean_log_exit_zero(tmp_path):
    # Tek basarili giris -> hicbir kural tetiklenmez -> exit 0.
    p = tmp_path / "clean.log"
    p.write_text(
        "Jun  1 05:54:00 web-01 sshd[1]: Accepted password for alice from 198.51.100.5 port 60050 ssh2\n",
        encoding="utf-8",
    )
    code, out = _run([str(p)])
    assert code == 0
    assert "Alarm yok" in out


def test_sample_log_reports_alerts():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, out = _run([str(SAMPLE_LOG)])
    assert code == 1                       # alarm var -> exit 1
    assert "ALARMLAR" in out
    assert "OZET" in out
    assert "fail_then_success" in out      # ornek logta beklenen yuksek oncelikli alarm


def test_quiet_skips_summary():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, out = _run([str(SAMPLE_LOG), "--quiet"])
    assert "OZET" not in out               # --quiet ozet/IP tablosunu atlar
    assert "ALARMLAR" in out


def test_json_output_written(tmp_path):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    out_json = tmp_path / "rapor.json"
    code, out = _run([str(SAMPLE_LOG), "--json", str(out_json)])
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "summary" in data and "events" in data and "alerts" in data
    assert data["summary"]["alarm_sayisi"] == len(data["alerts"])
    assert f"JSON rapor yazildi: {out_json}" in out


def test_allow_suppresses_alerts_for_ip():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    # 192.0.2.10 brute_force uretiyordu; allowlist'e alinca o IP'nin ALARMI dusmeli.
    # --quiet ile sadece alarm bolumune bakariz (allowlist ozet/IP tablosunu degil,
    # tespiti filtreler; IP yine olay listesinde gorunur, bu dogru davranis).
    _, out_all = _run([str(SAMPLE_LOG), "--quiet"])
    _, out_allow = _run([str(SAMPLE_LOG), "--quiet", "--allow", "192.0.2.10"])
    assert "192.0.2.10" in out_all
    assert "192.0.2.10" not in out_allow


# --------------------------------------------------------------------------- #
# TERMINAL KACIS DIZISI ENJEKSIYONU (CWE-117)
# --------------------------------------------------------------------------- #
def test_control_characters_are_neutralised(tmp_path):
    """
    Log satirlari SALDIRGAN kontrolundedir: 'Invalid user <ESC>[2J' gibi bir
    kullanici adiyla baglanmak yeterlidir. Ham satir kanit olarak basilirsa
    kacis dizileri analistin terminalinde CALISIR (ekran temizleme, pencere
    basligi degistirme, onceki alarmlari sahte metinle ezme).
    """
    p = tmp_path / "ansi.log"
    p.write_text(
        "".join(
            f"Jun  1 05:50:0{i} web-01 sshd[1]: Failed password for "
            f"r\x1b[2m\x1b]0;PWNED\x07oot from 192.0.2.10 port 5432{i} ssh2\n"
            for i in range(6)
        ),
        encoding="utf-8",
    )
    _, out = _run([str(p), "--quiet", "--no-color"])
    assert "\x1b" not in out            # ham ESC ciktiya SIZMAMALI
    assert "\x07" not in out            # BEL de (pencere basligi sonlandirici)
    assert r"\x1b" in out               # ama gizlendigi GORUNMELI (metin olarak)
    assert "brute_force" in out         # tespit yine de calismali


def test_json_output_keeps_raw_bytes(tmp_path):
    """
    Temizleme yalnizca GOSTERIM icindir. --json ham kaniti korumali
    (json.dumps kacislari \\u001b olarak guvenle kodlar).
    """
    p = tmp_path / "ansi.log"
    p.write_text(
        "".join(
            f"Jun  1 05:50:0{i} web-01 sshd[1]: Failed password for "
            f"r\x1b[2moot from 192.0.2.10 port 5432{i} ssh2\n"
            for i in range(6)
        ),
        encoding="utf-8",
    )
    out_json = tmp_path / "r.json"
    _run([str(p), "--json", str(out_json)])
    raw = out_json.read_text(encoding="utf-8")
    assert "\\u001b" in raw                        # dosyada kacisli olarak kodlu
    data = json.loads(raw)
    assert "\x1b" in data["events"][0]["raw_line"]  # cozuldugunde ham hali geri gelir


# --------------------------------------------------------------------------- #
# BAYRAK BAGLANTISI — CLI bayraklari gercekten kurallara ulasmali
# --------------------------------------------------------------------------- #
def test_new_flag_defaults():
    args = cli.build_parser().parse_args(["auth.log"])
    assert args.min_fails == 3
    assert args.success_window == 600
    assert args.anomaly_k == 2.0
    assert args.anomaly_min_volume == 5
    assert args.no_color is False


def test_threshold_flag_changes_result():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, low = _run([str(SAMPLE_LOG), "--quiet", "--threshold", "5"])
    _, high = _run([str(SAMPLE_LOG), "--quiet", "--threshold", "500"])
    assert "brute_force" in low
    assert "brute_force" not in high


def test_min_fails_flag_changes_result():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, normal = _run([str(SAMPLE_LOG), "--quiet"])
    _, tuned = _run([str(SAMPLE_LOG), "--quiet", "--min-fails", "99"])
    assert "fail_then_success" in normal
    assert "fail_then_success" not in tuned


def test_enum_threshold_flag_changes_result():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, normal = _run([str(SAMPLE_LOG), "--quiet"])
    _, tuned = _run([str(SAMPLE_LOG), "--quiet", "--enum-threshold", "99"])
    assert "user_enumeration" in normal
    assert "user_enumeration" not in tuned


def test_anomaly_flags_change_result():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, normal = _run([str(SAMPLE_LOG), "--quiet"])
    _, tuned = _run([str(SAMPLE_LOG), "--quiet", "--anomaly-k", "1000"])
    assert "anomalous_ip" in normal
    assert "anomalous_ip" not in tuned


def test_sudo_flag_defaults_and_overrides():
    args = cli.build_parser().parse_args(["auth.log"])
    assert (args.sudo_window, args.sudo_threshold) == (300, 3)
    args = cli.build_parser().parse_args(["auth.log", "--sudo-window", "60", "--sudo-threshold", "5"])
    assert (args.sudo_window, args.sudo_threshold) == (60, 5)


def _json_report(tmp_path, *extra):
    """Ornek logu --json ile calistir; (exit_code, rapor) dondur. Terminal metni parse edilmez."""
    out_json = tmp_path / "r.json"
    code, _ = _run([str(SAMPLE_LOG), "--quiet", "--json", str(out_json), *extra])
    return code, json.loads(out_json.read_text(encoding="utf-8"))


def test_sample_defaults_unchanged_and_no_sudo_alert(tmp_path):
    # Ornekte yalnizca 2 sudo basarisizligi var; varsayilan esik 3 -> kural tetiklenmez.
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, data = _json_report(tmp_path)
    s = data["summary"]
    assert (s["toplam_olay"], s["basarisiz_giris"], s["alarm_sayisi"]) == (36, 31, 6)
    assert "sudo_brute_force" not in {a["rule_name"] for a in data["alerts"]}
    assert code == 1


def test_sudo_threshold_flag_triggers_rule_on_sample(tmp_path):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, default = _json_report(tmp_path)
    code, tuned = _json_report(tmp_path, "--sudo-threshold", "2")
    assert code == 1
    assert tuned["summary"]["alarm_sayisi"] == 7
    sudo = [a for a in tuned["alerts"] if a["rule_name"] == "sudo_brute_force"]
    assert len(sudo) == 1
    assert sudo[0]["source_ip"] is None
    assert sudo[0]["count"] == 2
    assert sudo[0]["description"].startswith("bob@web-01:")
    # Diger kurallarin alarmlari aynen korunur.
    others = sorted(a["rule_name"] for a in tuned["alerts"] if a["rule_name"] != "sudo_brute_force")
    assert others == sorted(a["rule_name"] for a in default["alerts"])


def test_sudo_window_flag_reaches_rule(tmp_path):
    # Ornekteki 2 sudo basarisizligi 5 sn arayla: pencere 4 sn ile ayni pencereye sigmaz.
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    _, data = _json_report(tmp_path, "--sudo-threshold", "2", "--sudo-window", "4")
    assert "sudo_brute_force" not in {a["rule_name"] for a in data["alerts"]}


@pytest.mark.parametrize("flag,value", [("--sudo-threshold", "0"), ("--sudo-window", "-1")])
def test_invalid_sudo_config_returns_2(flag, value):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, _ = _run([str(SAMPLE_LOG), flag, value])
    assert code == 2


def test_sudo_alert_description_is_neutralised(tmp_path):
    """sudo alarm aciklamasi log'dan gelen kullanici adini icerir -> terminalde temizlenmeli."""
    p = tmp_path / "sudo.log"
    p.write_text(
        "".join(
            f"Jun  1 05:52:4{i} web-01 sudo: pam_unix(sudo:auth): authentication failure; "
            f"logname=x uid=1000 euid=0 tty=/dev/pts/0 ruser=b\x1b[2Job rhost=  user=root\n"
            for i in range(3)
        ),
        encoding="utf-8",
    )
    code, out = _run([str(p), "--quiet", "--no-color"])
    assert code == 1
    assert "sudo_brute_force" in out
    assert "\x1b" not in out
    assert r"b\x1b[2Job@web-01" in out


# --------------------------------------------------------------------------- #
# HATA YOLLARI ve KUCUK DALLAR
# --------------------------------------------------------------------------- #
def test_invalid_detection_config_returns_2():
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, _ = _run([str(SAMPLE_LOG), "--window", "-1"])
    assert code == 2                       # traceback degil, kullanim hatasi


def test_directory_as_logfile_returns_2(tmp_path):
    code, _ = _run([str(tmp_path)])        # dizin -> OSError (IsADirectoryError/PermissionError)
    assert code == 2


def test_json_to_unwritable_path_returns_2(tmp_path):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    bad = tmp_path / "yok" / "olmayan" / "r.json"
    code, _ = _run([str(SAMPLE_LOG), "--json", str(bad)])
    assert code == 2


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert cli.__version__ in capsys.readouterr().out


def test_color_output_contains_ansi_when_enabled(tmp_path):
    """_color(enabled=True) yolu: renkli terminalde ANSI kodu URETILMELI."""
    assert "\x1b[91m" in cli._color("x", "high", True)
    assert cli._color("x", "high", False) == "x"


def test_alert_without_ip_or_evidence_prints(tmp_path):
    """source_ip=None / evidence=[] dallari cokmeden basilmali."""
    import io
    from detection.alert import Alert, Severity
    buf = io.StringIO()
    cli._print_alerts(
        [Alert(rule_name="r", severity=Severity.LOW, source_ip=None, count=1,
               time_window=None, description="aciklama", evidence=[])],
        color=False, out=buf,
    )
    text = buf.getvalue()
    assert "aciklama" in text
    assert "IP        :" not in text
    assert "Kanit" not in text


def test_top_ips_empty_prints_nothing():
    import io
    from storage.store import EventStore
    buf = io.StringIO()
    cli._print_top_ips(EventStore(), out=buf)
    assert buf.getvalue() == ""


# --------------------------------------------------------------------------- #
# su_brute_force — gecici gercekci su loglariyla
# --------------------------------------------------------------------------- #
def _su_line(sec: int, actor: str, target: str) -> str:
    return (f"Jun  1 05:55:{sec:02d} web-01 su: pam_unix(su:auth): authentication failure; "
            f"logname={actor} uid=1000 euid=0 tty=pts/0 ruser={actor} rhost=  user={target}\n")


def _write_su_log(tmp_path, pairs):
    p = tmp_path / "su.log"
    p.write_text("".join(_su_line(i * 5, a, t) for i, (a, t) in enumerate(pairs)), encoding="utf-8")
    return p


def _json_for(tmp_path, log, *extra):
    out_json = tmp_path / "su.json"
    code, _ = _run([str(log), "--quiet", "--json", str(out_json), *extra])
    return code, json.loads(out_json.read_text(encoding="utf-8"))


def test_su_flag_defaults_and_overrides():
    args = cli.build_parser().parse_args(["auth.log"])
    assert (args.su_window, args.su_threshold) == (300, 3)
    args = cli.build_parser().parse_args(["auth.log", "--su-window", "60", "--su-threshold", "5"])
    assert (args.su_window, args.su_threshold) == (60, 5)


@pytest.mark.parametrize("flag,value", [("--su-threshold", "0"), ("--su-window", "-1")])
def test_invalid_su_config_returns_2(flag, value):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, _ = _run([str(SAMPLE_LOG), flag, value])
    assert code == 2


def test_sample_has_no_su_alert_by_default(tmp_path):
    if not SAMPLE_LOG.exists():
        pytest.skip("sample_auth.log yok")
    code, data = _json_report(tmp_path)
    assert (data["summary"]["toplam_olay"], data["summary"]["basarisiz_giris"],
            data["summary"]["alarm_sayisi"]) == (36, 31, 6)
    assert "su_brute_force" not in {a["rule_name"] for a in data["alerts"]}
    assert code == 1


def test_su_actor_switching_targets_triggers_rule(tmp_path):
    log = _write_su_log(tmp_path, [("alice", "root"), ("alice", "postgres"), ("alice", "deploy")])
    code, data = _json_for(tmp_path, log)
    assert code == 1
    evs = data["events"]
    assert [e["event_type"] for e in evs] == ["SU_FAILURE"] * 3
    assert {e["actor_username"] for e in evs} == {"alice"}
    assert [e["username"] for e in evs] == ["root", "postgres", "deploy"]
    su = [a for a in data["alerts"] if a["rule_name"] == "su_brute_force"]
    assert len(su) == 1
    assert su[0]["severity"] == "medium"
    assert su[0]["source_ip"] is None
    assert su[0]["description"].startswith("alice@web-01:")
    assert "hedefler: deploy, postgres, root;" in su[0]["description"]


def test_su_different_actors_same_target_do_not_combine(tmp_path):
    log = _write_su_log(tmp_path, [("alice", "root"), ("bob", "root"), ("charlie", "root")])
    code, data = _json_for(tmp_path, log)
    assert "su_brute_force" not in {a["rule_name"] for a in data["alerts"]}
    assert code == 0


def test_su_threshold_flag_reaches_rule(tmp_path):
    log = _write_su_log(tmp_path, [("alice", "root")] * 3)
    _, data = _json_for(tmp_path, log, "--su-threshold", "4")
    assert "su_brute_force" not in {a["rule_name"] for a in data["alerts"]}


def test_su_alert_output_is_neutralised(tmp_path):
    """Aktor ve hedef log'dan gelir; terminalde kontrol karakterleri etkisiz olmali."""
    log = _write_su_log(tmp_path, [("al\x1b[2Jice", "ro\x1b]0;X\x07ot")] * 3)
    code, out = _run([str(log), "--quiet", "--no-color"])
    assert code == 1
    assert "su_brute_force" in out
    assert "\x1b" not in out and "\x07" not in out
    assert r"al\x1b[2Jice@web-01" in out
