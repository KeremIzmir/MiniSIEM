"""
test_auth_parser.py — auth.log -> Event cevriminin birim testleri.

Her olay turu icin bir ornek satir; ayrica yil cikarimi, taninmayan satir
(unparsed) ve baslik-eslesip-govde-eslesmeyen (UNKNOWN) kenar durumlari.
"""

from datetime import datetime

import pytest

from parser.events import EventType
from parser.auth_parser import parse_line, parse_lines, parse_file


# Sabit referans an: yil cikarimi testleri gercek saate bagli kalmasin.
NOW = datetime(2026, 6, 27, 12, 0, 0)


def test_failed_password():
    line = "Jun  1 05:50:01 web-01 sshd[12010]: Failed password for root from 192.0.2.10 port 54321 ssh2"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.event_type == EventType.FAILED_PASSWORD
    assert e.username == "root"
    assert e.source_ip == "192.0.2.10"
    assert e.port == 54321
    assert e.host == "web-01"
    assert e.process == "sshd"
    assert e.is_failure and not e.is_success


def test_failed_password_invalid_user_prefix():
    # "invalid user" oneki yutulur ama tur yine FAILED_PASSWORD; kullanici adi saf alinir.
    line = "Jun  1 05:51:05 web-01 sshd[12050]: Failed password for invalid user admin from 192.0.2.20 port 41001 ssh2"
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.FAILED_PASSWORD
    assert e.username == "admin"
    assert e.source_ip == "192.0.2.20"


def test_accepted_password():
    line = "Jun  1 05:54:00 web-01 sshd[12400]: Accepted password for alice from 198.51.100.5 port 60050 ssh2"
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.ACCEPTED_LOGIN
    assert e.username == "alice"
    assert e.is_success and not e.is_failure


def test_accepted_publickey():
    line = "Jun  1 05:53:00 web-01 sshd[12200]: Accepted publickey for deploy from 198.51.100.9 port 60010 ssh2"
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.ACCEPTED_LOGIN
    assert e.username == "deploy"


def test_invalid_user_without_port():
    line = "Jun  1 05:51:02 web-01 sshd[12050]: Invalid user oracle from 192.0.2.20"
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.INVALID_USER
    assert e.username == "oracle"
    assert e.source_ip == "192.0.2.20"
    assert e.port is None


def test_sudo_failure_has_no_ip():
    line = ("Jun  1 05:52:40 web-01 sudo:    bob : pam_unix(sudo:auth): authentication failure; "
            "logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.SUDO_FAILURE
    assert e.process == "sudo"
    assert e.username == "bob"
    assert e.source_ip is None        # sudo'da rhost bos -> None
    assert e.is_failure


def test_sshd_pam_failure_takes_rhost_ip():
    line = ("Jun  1 05:53:05 web-01 sshd[12210]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.40  user=root")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.AUTH_FAILURE
    assert e.source_ip == "192.0.2.40"   # sshd'de rhost dolu -> IP olarak alinir
    assert e.username == "root"


def test_header_ok_body_unknown():
    # Baslik taninir ama govde hicbir kurala uymaz -> bilgi kaybolmasin, UNKNOWN dön.
    line = "Jun  1 05:53:30 web-01 CRON[12300]: pam_unix(cron:session): session opened for user root by (uid=0)"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.event_type == EventType.UNKNOWN
    assert e.host == "web-01"
    assert e.process == "CRON"


def test_unparsed_line_returns_none():
    # Syslog basligi bile yok -> None (cagiran taraf 'unparsed' sayar).
    assert parse_line("bu bir auth.log satiri degil", now=NOW) is None


def test_empty_line_returns_none():
    assert parse_line("", now=NOW) is None
    assert parse_line("   \n", now=NOW) is None


def test_year_inference_rolls_back_across_new_year():
    # Su an Ocak; log 'Dec' diyorsa bu GECEN yila aittir -> yil bir geri alinir.
    jan = datetime(2026, 1, 5, 10, 0, 0)
    line = "Dec 31 23:59:59 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    e = parse_line(line, now=jan)
    assert e.timestamp.year == 2025


def test_year_inference_uses_current_year_normally():
    line = "Jun  1 05:50:01 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    e = parse_line(line, now=NOW)
    assert e.timestamp.year == 2026


def test_parse_lines_splits_events_and_unparsed():
    lines = [
        "Jun  1 05:50:01 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2",
        "tamamen alakasiz satir",
        "",  # bos satir sayilmaz
        "Jun  1 05:50:09 web-01 sshd[1]: Accepted password for alice from 198.51.100.5 port 60000 ssh2",
    ]
    events, unparsed = parse_lines(lines, now=NOW)
    assert len(events) == 2
    assert unparsed == ["tamamen alakasiz satir"]


def test_parse_file(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Jun  1 05:50:01 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "cop satir\n",
        encoding="utf-8",
    )
    events, unparsed = parse_file(str(p), now=NOW)
    assert len(events) == 1
    assert len(unparsed) == 1


# --------------------------------------------------------------------------- #
# ARTIK YIL (leap year) — tek bozuk satir TUM dosyayi cokertmemeli
# --------------------------------------------------------------------------- #
def test_feb29_falls_back_to_nearest_leap_year():
    """
    'Feb 29' satiri, referans yil artik yil DEGILSE eskiden ValueError firlatip
    parse_file'i tamamen cokertiyordu. Artik en yakin gecerli (artik) yila duser.
    """
    line = "Feb 29 12:00:00 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    e = parse_line(line, reference_year=2026, now=datetime(2026, 3, 1, 12, 0, 0))
    assert e is not None
    assert e.timestamp.year == 2024        # 2026 ve 2025 artik degil -> 2024
    assert e.timestamp.month == 2 and e.timestamp.day == 29


def test_feb29_keeps_reference_year_when_it_is_a_leap_year():
    line = "Feb 29 12:00:00 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    e = parse_line(line, reference_year=2028, now=datetime(2028, 3, 1, 12, 0, 0))
    assert e.timestamp.year == 2028


def test_feb29_year_rollback_does_not_crash():
    """Yil geri alma yolunda da (log gelecekte gorunuyor) cokme olmamali."""
    line = "Feb 29 12:00:00 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    e = parse_line(line, reference_year=2028, now=datetime(2027, 3, 1, 12, 0, 0))
    assert e is not None and e.timestamp.month == 2 and e.timestamp.day == 29


def test_impossible_date_is_unparsed_not_crash():
    """'Feb 31' hicbir yilda gecerli degil -> istisna degil, unparsed."""
    line = "Feb 31 12:00:00 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2"
    assert parse_line(line, now=NOW) is None


def test_bad_date_line_does_not_abort_whole_file(tmp_path):
    """
    EN ONEMLI DAVRANIS: tek gecersiz tarih satiri, dosyanin GERI KALANINI
    yutmamali. Eskiden ilk bozuk satirda ValueError ile tum parse cokerdi.
    """
    p = tmp_path / "auth.log"
    p.write_text(
        "Jun  1 05:50:01 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Feb 31 12:00:00 web-01 sshd[1]: Failed password for root from 192.0.2.11 port 22 ssh2\n"
        "Jun  1 05:50:09 web-01 sshd[1]: Accepted password for alice from 198.51.100.5 port 60000 ssh2\n",
        encoding="utf-8",
    )
    events, unparsed = parse_file(str(p), now=NOW)
    assert len(events) == 2          # bozuk satirdan SONRAKI satir da islendi
    assert len(unparsed) == 1


def test_parse_file_replaces_bad_bytes(tmp_path):
    """errors='replace' sozlesmesi: bozuk bayt cokme degil, degistirme uretir."""
    p = tmp_path / "auth.log"
    p.write_bytes(
        b"Jun  1 05:50:01 web-01 sshd[1]: Failed password for r\xffot from 192.0.2.10 port 22 ssh2\n"
    )
    events, unparsed = parse_file(str(p), now=NOW)
    assert len(events) == 1
    assert unparsed == []
    assert "�" in events[0].username     # U+FFFD REPLACEMENT CHARACTER
