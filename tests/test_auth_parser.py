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


# --- PAM alanlari: 'user=' asla 'ruser=' icinden eslesmemeli ---------------- #
# sudo icin kullanici = komutu calistiran aktor: ruser > logname > user.
# su icin kullanici = HEDEF hesap ('user='); aktor ayrica actor_username'de tutulur.
# Diger PAM olaylari (sshd, login ...) hedef hesabi, yani 'user=' alanini kullanir.

_SUDO_PAM = ("Jun  1 05:52:40 web-01 sudo: pam_unix(sudo:auth): authentication failure; "
             "logname={logname} uid=1000 euid=0 tty=/dev/pts/0 ruser={ruser} rhost=  user={user}")


def test_sudo_pam_prefers_ruser_over_target_user():
    # rootpw/targetpw: parola root icin sorulur ama deneyen aktor alice.
    e = parse_line(_SUDO_PAM.format(logname="alice", ruser="alice", user="root"), now=NOW)
    assert e.event_type == EventType.SUDO_FAILURE
    assert e.username == "alice"
    assert e.source_ip is None


def test_sudo_pam_falls_back_to_logname():
    e = parse_line(_SUDO_PAM.format(logname="bob", ruser="", user="root"), now=NOW)
    assert e.event_type == EventType.SUDO_FAILURE
    assert e.username == "bob"


def test_sudo_pam_falls_back_to_target_user():
    e = parse_line(_SUDO_PAM.format(logname="", ruser="", user="bob"), now=NOW)
    assert e.event_type == EventType.SUDO_FAILURE
    assert e.username == "bob"


def test_non_sudo_pam_uses_target_user_even_when_ruser_set():
    # Eski regex 'user=' anahtarini 'ruser=alice' icinde bulup alice donduruyordu.
    # (su artik SU_FAILURE oldugu icin genel PAM yolu 'login' ile sabitlenir.)
    line = ("Jun  1 05:52:40 web-01 login[900]: pam_unix(login:auth): authentication failure; "
            "logname=alice uid=0 euid=0 tty=tty1 ruser=alice rhost=  user=root")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.AUTH_FAILURE
    assert e.username == "root"
    assert e.source_ip is None
    assert e.actor_username is None     # genel PAM olaylarinda aktor cikarilmaz


def test_pam_rhost_captured_when_ruser_set():
    # Ayni hata: ruser doluyken rhost grubu atlaniyor ve kaynak IP kayboluyordu.
    line = ("Jun  1 05:53:05 web-01 sshd[12210]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser=svc rhost=192.0.2.40  user=root")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.AUTH_FAILURE
    assert e.username == "root"
    assert e.source_ip == "192.0.2.40"


def test_pam_failure_without_target_user_stays_unknown():
    # Hedef 'user=' alani yoksa olay siniflandirilmaz, UNKNOWN kalir. (Eski regex
    # bu satiri 'ruser=bob' icindeki 'user=bob' ile yanlislikla SUDO_FAILURE yapiyordu.)
    line = ("Jun  1 05:52:40 web-01 sudo: pam_unix(sudo:auth): authentication failure; "
            "logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.UNKNOWN
    assert e.username is None


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


# --- su: hedef hesap username'de, isteyen aktor actor_username'de ------------ #
# PAM 'user=' = gecilmek istenen HEDEF hesap; 'ruser' / 'logname' = su'yu calistiran
# AKTOR. 'user=' asla aktorun yedegi degildir.

_SU_PAM = ("Jun  1 05:55:00 web-01 {proc}: pam_unix(su:auth): authentication failure; "
           "logname={logname} uid=1000 euid=0 tty=pts/0 ruser={ruser} rhost=  user={user}")


def test_su_pam_failure_classified_with_actor_and_target():
    e = parse_line(_SU_PAM.format(proc="su", logname="alice", ruser="alice", user="root"), now=NOW)
    assert e.event_type == EventType.SU_FAILURE
    assert e.process == "su"
    assert e.username == "root"             # hedef
    assert e.actor_username == "alice"      # aktor
    assert e.source_ip is None
    assert e.port is None
    assert e.is_failure and not e.is_success


def test_su_actor_prefers_ruser_over_logname():
    e = parse_line(_SU_PAM.format(proc="su", logname="session-user", ruser="alice", user="root"), now=NOW)
    assert e.actor_username == "alice"
    assert e.username == "root"


def test_su_actor_falls_back_to_logname():
    e = parse_line(_SU_PAM.format(proc="su", logname="bob", ruser="", user="root"), now=NOW)
    assert e.event_type == EventType.SU_FAILURE
    assert e.actor_username == "bob"
    assert e.username == "root"


def test_su_missing_actor_is_none_never_target():
    # ruser ve logname bos: aktor bilinmiyor. 'user=root' ASLA aktor yapilmaz.
    e = parse_line(_SU_PAM.format(proc="su", logname="", ruser="", user="root"), now=NOW)
    assert e.event_type == EventType.SU_FAILURE
    assert e.username == "root"
    assert e.actor_username is None


def test_su_without_target_user_stays_unknown():
    line = ("Jun  1 05:55:00 web-01 su: pam_unix(su:auth): authentication failure; "
            "logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.UNKNOWN
    assert e.actor_username is None


def test_su_with_pid_header():
    e = parse_line(_SU_PAM.format(proc="su[1234]", logname="alice", ruser="alice", user="root"), now=NOW)
    assert e.event_type == EventType.SU_FAILURE
    assert e.process == "su"
    assert e.actor_username == "alice"


def test_sudo_keeps_username_semantics_and_exposes_actor():
    # username davranisi PR #4'teki gibi kalir; aktor ayrica actor_username'de.
    e = parse_line(_SUDO_PAM.format(logname="alice", ruser="alice", user="root"), now=NOW)
    assert (e.event_type, e.username, e.actor_username) == (EventType.SUDO_FAILURE, "alice", "alice")
    e = parse_line(_SUDO_PAM.format(logname="bob", ruser="", user="root"), now=NOW)
    assert (e.username, e.actor_username) == ("bob", "bob")


def test_sudo_without_actor_keeps_target_fallback_but_actor_is_none():
    e = parse_line(_SUDO_PAM.format(logname="", ruser="", user="bob"), now=NOW)
    assert e.event_type == EventType.SUDO_FAILURE
    assert e.username == "bob"              # mevcut geriye uyumlu yedek
    assert e.actor_username is None          # ama hedef aktor yapilmaz


def test_sshd_pam_has_no_actor():
    line = ("Jun  1 05:53:05 web-01 sshd[12210]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.40  user=root")
    e = parse_line(line, now=NOW)
    assert (e.event_type, e.username, e.source_ip, e.actor_username) == (
        EventType.AUTH_FAILURE, "root", "192.0.2.40", None)


@pytest.mark.parametrize("proc,svc,user", [("su", "su", "root"), ("sudo", "sudo", "bob")])
def test_pam_retry_summary_lines_are_not_counted_failures(proc, svc, user):
    # pam_unix ayni PAM islemindeki ek hatalari "N more authentication failures"
    # ozetiyle yazar. Bunlar sayilan olay OLMAMALI (cift sayim olurdu).
    line = (f"Jun  1 05:55:10 web-01 {proc}: pam_unix({svc}:auth): 2 more authentication failures; "
            f"logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user={user}")
    e = parse_line(line, now=NOW)
    assert e.event_type not in (EventType.SU_FAILURE, EventType.SUDO_FAILURE)
    assert e.event_type == EventType.UNKNOWN
    assert not e.is_failure


# --- Event modeli: geriye uyumluluk ------------------------------------------ #

def test_event_without_actor_argument_defaults_to_none():
    from parser.events import Event
    e = Event(NOW, "web-01", "sshd", EventType.FAILED_PASSWORD, "root", "192.0.2.1", 22, "raw")
    assert e.actor_username is None


def test_event_to_dict_includes_actor_username():
    e = parse_line(_SU_PAM.format(proc="su", logname="alice", ruser="alice", user="root"), now=NOW)
    d = e.to_dict()
    assert d["actor_username"] == "alice"
    assert d["event_type"] == "SU_FAILURE"
    assert d["username"] == "root"


# --- SU_SUCCESS: util-linux su'nun basari kaydi "(to <hedef>) <aktor> on <tty>" -- #
# Tek (kanonik) basari kaynagi budur. PAM "session opened/closed" ve "FAILED SU"
# satirlari BILINCLI olarak UNKNOWN kalir (cift sayim ve farkli aktor kaynagi).

_SU_OK = "Jun  1 05:55:10 web-01 {proc}: {body}"


def test_su_success_record_classified():
    e = parse_line(_SU_OK.format(proc="su[1234]", body="(to root) alice on pts/0"), now=NOW)
    assert e.event_type == EventType.SU_SUCCESS
    assert e.process == "su"
    assert e.username == "root"               # hedef
    assert e.actor_username == "alice"        # aktor
    assert e.source_ip is None and e.port is None
    assert e.is_success is True
    assert e.is_failure is False


def test_su_success_non_root_target():
    e = parse_line(_SU_OK.format(proc="su[1234]", body="(to postgres) alice on pts/1"), now=NOW)
    assert (e.event_type, e.username, e.actor_username) == (EventType.SU_SUCCESS, "postgres", "alice")


def test_su_success_terminal_none():
    e = parse_line(_SU_OK.format(proc="su[1234]", body="(to root) alice on none"), now=NOW)
    assert e.event_type == EventType.SU_SUCCESS


def test_su_success_empty_actor_is_none():
    # util-linux aktoru bos yazarsa ayiriciler arasinda iki bosluk kalir.
    e = parse_line(_SU_OK.format(proc="su[1234]", body="(to root)  on pts/0"), now=NOW)
    assert e.event_type == EventType.SU_SUCCESS
    assert e.username == "root"
    assert e.actor_username is None


def test_su_success_without_pid_header():
    e = parse_line(_SU_OK.format(proc="su", body="(to root) alice on pts/0"), now=NOW)
    assert (e.event_type, e.process) == (EventType.SU_SUCCESS, "su")


@pytest.mark.parametrize("body", [
    "(to ) alice on pts/0",              # hedef bos
    "(to root) alice pts/0",             # 'on' yok
    "(to root) alice on pts/0 extra",    # sonda fazlalik
    "to root alice on pts/0",            # parantez yok
])
def test_malformed_su_success_record_stays_unknown(body):
    e = parse_line(_SU_OK.format(proc="su[1234]", body=body), now=NOW)
    assert e.event_type == EventType.UNKNOWN


@pytest.mark.parametrize("body", [
    "FAILED SU (to root) alice on pts/0",
    "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
    "pam_unix(su-l:session): session opened for user root(uid=0) by alice(uid=1000)",
    "pam_unix(su:session): session closed for user root",
])
def test_non_canonical_su_records_stay_unknown(body):
    e = parse_line(_SU_OK.format(proc="su[1234]", body=body), now=NOW)
    assert e.event_type == EventType.UNKNOWN
    assert not e.is_success and not e.is_failure


@pytest.mark.parametrize("proc", ["runuser[77]", "sshd[1]", "login[9]"])
def test_success_body_from_other_process_is_not_su_success(proc):
    e = parse_line(_SU_OK.format(proc=proc, body="(to root) alice on pts/0"), now=NOW)
    assert e.event_type != EventType.SU_SUCCESS
    assert e.event_type == EventType.UNKNOWN


def test_su_l_pam_failure_is_already_su_failure():
    # util-linux 'su -l': PAM servisi su-l, dis syslog etiketi yine 'su'.
    line = ("Jun  1 05:55:00 web-01 su[1234]: pam_unix(su-l:auth): authentication failure; "
            "logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root")
    e = parse_line(line, now=NOW)
    assert (e.event_type, e.process, e.username, e.actor_username) == (
        EventType.SU_FAILURE, "su", "root", "alice")


def test_su_success_to_dict():
    d = parse_line(_SU_OK.format(proc="su[1234]", body="(to root) alice on pts/0"), now=NOW).to_dict()
    assert (d["event_type"], d["username"], d["actor_username"]) == ("SU_SUCCESS", "root", "alice")


def test_accepted_login_is_still_success():
    line = "Jun  1 05:54:00 web-01 sshd[12400]: Accepted password for alice from 198.51.100.5 port 60050 ssh2"
    e = parse_line(line, now=NOW)
    assert e.is_success and not e.is_failure



# --- sudo "N incorrect password attempt(s)" ozet kaydi ------------------------- #
# sudoers'in cagri basina yazdigi TOPLU kayit. Birincil PAM basarisizligi (SUDO_FAILURE)
# DEGILDIR: is_failure/is_success ikisi de False, hicbir sayaca/kurala girmez.

_SUDO_SUM = "Jun  1 05:52:10 web-01 {proc}: {body}"
_TRAIL = " ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"


def test_event_type_and_attempt_count_field_exist():
    import dataclasses
    from parser.events import Event
    assert EventType.SUDO_INCORRECT_PASSWORD_SUMMARY.value == "SUDO_INCORRECT_PASSWORD_SUMMARY"
    fields = [f.name for f in dataclasses.fields(Event)]
    assert fields[-2:] == ["actor_username", "attempt_count"]      # en sonda, varsayilanli


def test_legacy_event_construction_defaults_attempt_count_to_none():
    from parser.events import Event
    e = Event(NOW, "web-01", "sshd", EventType.FAILED_PASSWORD, "root", "192.0.2.1", 22, "raw")
    assert e.attempt_count is None
    assert e.to_dict()["attempt_count"] is None


@pytest.mark.parametrize("count,noun", [(1, "attempt"), (2, "attempts"), (3, "attempts")])
def test_sudo_summary_parsed(count, noun):
    body = f"alice : {count} incorrect password {noun}{_TRAIL}"
    e = parse_line(_SUDO_SUM.format(proc="sudo[1234]", body=body), now=NOW)
    assert e.event_type == EventType.SUDO_INCORRECT_PASSWORD_SUMMARY
    assert e.process == "sudo"
    assert (e.username, e.actor_username, e.attempt_count) == ("alice", "alice", count)
    assert e.source_ip is None and e.port is None
    assert e.is_failure is False and e.is_success is False


def test_sudo_summary_to_dict():
    body = "alice : 3 incorrect password attempts" + _TRAIL
    d = parse_line(_SUDO_SUM.format(proc="sudo[1234]", body=body), now=NOW).to_dict()
    assert (d["event_type"], d["attempt_count"], d["username"]) == ("SUDO_INCORRECT_PASSWORD_SUMMARY", 3, "alice")


def test_sudo_summary_without_pid_header():
    e = parse_line(_SUDO_SUM.format(proc="sudo", body="alice : 3 incorrect password attempts" + _TRAIL), now=NOW)
    assert (e.event_type, e.process) == (EventType.SUDO_INCORRECT_PASSWORD_SUMMARY, "sudo")


def test_sudo_summary_without_trailing_fields():
    e = parse_line(_SUDO_SUM.format(proc="sudo", body="alice : 3 incorrect password attempts"), now=NOW)
    assert (e.event_type, e.attempt_count) == (EventType.SUDO_INCORRECT_PASSWORD_SUMMARY, 3)


def test_sudo_summary_command_with_spaces_and_semicolons():
    body = "alice : 2 incorrect password attempts ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c echo a ; echo b"
    e = parse_line(_SUDO_SUM.format(proc="sudo[9]", body=body), now=NOW)
    assert (e.event_type, e.attempt_count) == (EventType.SUDO_INCORRECT_PASSWORD_SUMMARY, 2)


def test_sudo_summary_max_parser_count():
    e = parse_line(_SUDO_SUM.format(proc="sudo", body="alice : 4294967295 incorrect password attempts"), now=NOW)
    assert e.attempt_count == 4294967295


@pytest.mark.parametrize("body", [
    "alice : 0 incorrect password attempts",               # sudo 0'i bu ifadeyle yazmaz
    "alice : 4294967296 incorrect password attempts",      # ayristirici ust siniri asildi
    "alice : 12345678901 incorrect password attempts",     # 10 haneden uzun
    "alice : 1 incorrect password attempts",               # tekil/cogul uyumsuz
    "alice : 2 incorrect password attempt",
    "alice : 3 incorrect password attempt",
    " : 3 incorrect password attempts",                    # aktor yok
    "alice : authentication rejected after 3 tries",       # ozel authfail_message
    "alice : 3 intentos de contrasena incorrectos",        # yerellestirilmis metin
    "alice : 3 incorrect password attemptsX",              # kelime sinirindan sonra cop
    "alice : -3 incorrect password attempts",
])
def test_invalid_sudo_summaries_stay_unknown(body):
    e = parse_line(_SUDO_SUM.format(proc="sudo[1234]", body=body + _TRAIL), now=NOW)
    assert e.event_type == EventType.UNKNOWN
    assert e.attempt_count is None


@pytest.mark.parametrize("proc", ["sshd[1]", "su[2]", "login[3]", "runuser[4]"])
def test_summary_body_from_other_process_is_not_summary(proc):
    e = parse_line(_SUDO_SUM.format(proc=proc, body="alice : 3 incorrect password attempts" + _TRAIL), now=NOW)
    assert e.event_type != EventType.SUDO_INCORRECT_PASSWORD_SUMMARY
    assert e.attempt_count is None


def test_sudo_pam_failure_unchanged_and_has_no_attempt_count():
    e = parse_line(_SUDO_PAM.format(logname="alice", ruser="alice", user="root"), now=NOW)
    assert (e.event_type, e.username, e.actor_username, e.attempt_count) == (EventType.SUDO_FAILURE, "alice", "alice", None)
    assert e.is_failure


def test_sudo_pam_more_failures_line_is_not_summary():
    line = ("Jun  1 05:52:40 web-01 sudo: pam_unix(sudo:auth): 2 more authentication failures; "
            "logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice")
    e = parse_line(line, now=NOW)
    assert e.event_type == EventType.UNKNOWN
    assert e.attempt_count is None


def test_sudo_accepted_command_line_stays_unknown():
    body = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
    e = parse_line(_SUDO_SUM.format(proc="sudo[1234]", body=body), now=NOW)
    assert e.event_type == EventType.UNKNOWN


def test_su_events_unaffected_by_summary_parser():
    ok = parse_line("Jun  1 05:55:10 web-01 su[1]: (to root) alice on pts/0", now=NOW)
    assert (ok.event_type, ok.attempt_count) == (EventType.SU_SUCCESS, None)
