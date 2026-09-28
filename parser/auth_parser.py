"""
auth_parser.py — Linux /var/log/auth.log satirlarini Event nesnelerine cevirir.

Bagimlilik: parser/events.py (Event, EventType).

TASARIM: Iki asamali parse.
  1) ONCE her satirin ortak "syslog basligini" ayikla (tarih, host, surec, mesaj).
  2) SONRA mesaj govdesini olay-turune ozel kucuk regex'lerle eslestir.
Bu ayrim onemli: baslik her satirda ayni; sadece mesaj kismi olaya gore degisir.
Tek dev regex yerine kucuk parcalar yazmak, hem okumayi hem hata ayiklamayi kolaylastirir.

auth.log ornek satirlari (gercek IP yok, RFC5737 test bloklari):
  Jun  1 05:50:01 web-01 sshd[12345]: Failed password for root from 192.0.2.10 port 54321 ssh2
  Jun  1 05:50:02 web-01 sshd[12345]: Failed password for invalid user admin from 192.0.2.10 port 54322 ssh2
  Jun  1 05:51:00 web-01 sshd[12345]: Accepted password for alice from 198.51.100.5 port 60000 ssh2
  Jun  1 05:51:30 web-01 sshd[12399]: Invalid user oracle from 192.0.2.20
  Jun  1 05:52:00 web-01 sudo: pam_unix(sudo:auth): authentication failure; ... rhost=  user=bob
"""

import re
from datetime import datetime
from typing import Iterable, Optional

from parser.events import Event, EventType


# --------------------------------------------------------------------------- #
# 1) ORTAK SYSLOG BASLIGI
# --------------------------------------------------------------------------- #
# Ornek: "Jun  1 05:50:01 web-01 sshd[12345]: <mesaj>"
#
# Grup grup aciklama:
#   (?P<month>[A-Z][a-z]{2})  -> "Jun" gibi 3 harfli ay kisaltmasi (bas harf buyuk).
#   \s+                        -> bir veya daha cok bosluk. NEDEN +? Cunku gun tek
#                                 haneliyse syslog iki bosluk koyar ("Jun  1"),
#                                 cift haneliyse tek bosluk ("Jun 10"). \s+ ikisini de yutar.
#   (?P<day>\d{1,2})           -> ayin gunu, 1 veya 2 hane.
#   (?P<time>\d{2}:\d{2}:\d{2}) -> HH:MM:SS, sabit format.
#   (?P<host>\S+)              -> bosluksuz host adi (orn 'web-01').
#   (?P<process>[\w.\-/]+?)    -> surec adi (sshd, sudo, CRON...). NON-GREEDY (+?):
#                                 mumkun olan EN AZ karakteri yesin ki hemen ardindaki
#                                 opsiyonel "[pid]" ya da ":" baslamadan dursun.
#                                 Greedy olsaydi "sshd[12345]" hepsini yutmaya calisirdi.
#   (?:\[(?P<pid>\d+)\])?      -> opsiyonel "[12345]" PID bloğu (sudo'da PID yok, o yuzden ?).
#   :\s+                       -> surec adindan sonra gelen iki nokta ust uste + bosluk.
#   (?P<message>.*)$           -> satirin geri kalani = asil olay mesaji.
_HEADER_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w.\-/]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


# --------------------------------------------------------------------------- #
# 2) MESAJ GOVDESINE OZEL REGEX'LER
# --------------------------------------------------------------------------- #
# Her biri yalnizca ilgili olay turunu yakalar. Sirayla denenir; ilk eslesen kazanir.

# "Failed password for root from 192.0.2.10 port 54321 ssh2"
# "Failed password for invalid user admin from 192.0.2.10 port 54322 ssh2"
#   (?:invalid user\s+)?  -> opsiyonel "invalid user " oneki. Bazen hatali parola
#                            var olmayan bir kullanici icin gelir; bu oneki yutariz
#                            ama olay turu yine FAILED_PASSWORD kalir (kullanici adini saf alalim).
#   (?P<user>\S+)         -> kullanici adi (bosluksuz).
#   from (?P<ip>\S+)      -> kaynak IP.
#   port (?P<port>\d+)    -> kaynak port.
_FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# "Accepted password for alice from 198.51.100.5 port 60000 ssh2"
# "Accepted publickey for deploy from 198.51.100.9 port 60010 ssh2"
#   (?:password|publickey) -> iki yontemden biri; degeri ayrica saklamiyoruz.
_ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# "Invalid user oracle from 192.0.2.20"
# "Invalid user oracle from 192.0.2.20 port 40000"
#   (?:\s+port\s+(?P<port>\d+))? -> port kismi opsiyonel; bazi surumler port yazmaz.
_INVALID_RE = re.compile(
    r"^Invalid user (?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)

# PAM kimlik dogrulama hatasi (hem sudo hem sshd):
#   "pam_unix(sudo:auth): authentication failure; logname=bob ... ruser=bob rhost=  user=bob"
#   "pam_unix(sshd:auth): authentication failure; ... ruser= rhost=192.0.2.30  user=root"
# Once "authentication failure;" sonrasini al, sonra anahtar=deger alanlarini tek tek ayir.
_PAM_RE = re.compile(r"authentication failure;(?P<fields>.*)$")

# Tek bir PAM alani: "anahtar=deger" (deger bos olabilir: "rhost=  user=bob").
#   (?<!\S) -> anahtar bir kelimenin ORTASINDAN baslayamaz. NEDEN: bu olmadan "user="
#              aramasi "ruser=alice" icindeki "user=alice"i yakalar — eski tek-regex
#              yaklasimi tam olarak bu hatayi yapiyordu (hem kullanici adi hem rhost bozuluyordu).
_PAM_FIELD_RE = re.compile(r"(?<!\S)(?P<key>\w+)=(?P<value>\S*)")


def _pam_fields(text: str) -> dict[str, str]:
    """PAM mesajindaki anahtar=deger alanlarini dict'e cevirir (ayni anahtar tekrarlanirsa ilki)."""
    fields: dict[str, str] = {}
    for m in _PAM_FIELD_RE.finditer(text):
        fields.setdefault(m["key"], m["value"])
    return fields


def _try_year(month: str, day: str, time_str: str, year: int) -> Optional[datetime]:
    """
    Verilen yil ile zaman damgasini kurmayi dener; imkansizsa None doner.

    NEDEN GEREKLI: "Feb 29" sadece ARTIK yillarda gecerlidir. Log yil bilgisi
    tasimadigi icin denedigimiz yil artik yil degilse strptime ValueError firlatir.
    Bu istisnayi burada yutariz ki cagiran taraf baska bir yil deneyebilsin.
    """
    try:
        # %Y %b %d %H:%M:%S -> ("2026", "Jun", "1", "05:50:01"). %d tek haneli gunu de kabul eder.
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _parse_timestamp(
    month: str,
    day: str,
    time_str: str,
    reference_year: int,
    now: Optional[datetime] = None,
) -> Optional[datetime]:
    """
    Syslog zaman damgasini datetime'a cevirir. Cozulemezse None doner.

    SORUN: auth.log YIL bilgisi icermez ("Jun  1 05:50:01"). Yili biz eklemeliyiz.
    YAKLASIM:
      - Varsayilan olarak 'reference_year' (genelde icinde bulundugumuz yil) kullan.
      - SINIR KONTROLU: Olusan tarih 'now'dan belirgin sekilde ILERIDE ise
        (orn. su an Ocak ama log 'Dec' diyorsa), bu log muhtemelen GECEN yila aittir;
        yili bir azalt. Bu, yilbasi gecislerinde tarihin gelecege kaymasini onler.

    ARTIK YIL TUZAGI: "Feb 29" satiri, denenen yil artik yil degilse gecersizdir.
    Eskiden bu ValueError firlatip TUM dosyanin parse'ini cokertiyordu. Artik
    sirayla (reference_year, reference_year-1) denenir; ikisi de tutmazsa
    en yakin onceki artik yila kadar geriye bakilir ve hicbiri olmazsa None doner
    (satir 'unparsed' sayilir — sessizce yanlis bir tarih uydurmayiz).
    """
    now = now or datetime.now()

    parsed = _try_year(month, day, time_str, reference_year)
    if parsed is not None:
        # 1 gunden fazla gelecekteyse: yil sinirini gecmis demektir -> bir yil geri al.
        # replace() yerine yeniden kurariz: 29 Subat, artik olmayan bir yila
        # replace edilemez (ValueError). Kurulamazsa referans yili oldugu gibi birakiriz.
        if parsed.timestamp() - now.timestamp() > 86400:
            earlier = _try_year(month, day, time_str, reference_year - 1)
            if earlier is not None:
                return earlier
        return parsed

    # reference_year ile kurulamadi (tipik olarak 29 Subat + artik olmayan yil).
    # En fazla 4 yil geriye bakip gecerli olan ilk yili kullan (artik yil periyodu 4).
    for delta in range(1, 5):
        candidate = _try_year(month, day, time_str, reference_year - delta)
        if candidate is not None:
            return candidate
    return None  # gercekten gecersiz tarih (orn "Feb 31") -> unparsed


def parse_line(
    line: str,
    reference_year: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Optional[Event]:
    """
    Tek bir auth.log satirini Event'e cevirir.

    Donus:
      - Event  : satir taninabildiyse.
      - None   : baslik eslesmediyse VEYA tarih gecerli degilse
                 (bu satir 'unparsed' sayilacak).
    Not: Baslik eslesip mesaj hicbir ozel kurala uymazsa, olayi yine de
    EventType.UNKNOWN olarak doneriz — boylece host/surec/zaman bilgisi kaybolmaz
    ve satir 'unparsed' degil 'taninan ama siniflandirilamayan' olur.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None  # bos satir

    header = _HEADER_RE.match(line)
    if not header:
        return None  # syslog basligi yok -> parse edilemedi

    reference_year = reference_year or (now or datetime.now()).year
    timestamp = _parse_timestamp(
        header["month"], header["day"], header["time"], reference_year, now
    )
    if timestamp is None:
        # Gecersiz tarih (orn "Feb 31"). Tek bozuk satir TUM dosyayi cokertmesin:
        # satiri unparsed say, isleme devam et.
        return None
    host = header["host"]
    process = header["process"]
    message = header["message"]

    # --- Olay turunu sirayla dene ---
    if m := _FAILED_RE.match(message):
        return Event(
            timestamp, host, process, EventType.FAILED_PASSWORD,
            username=m["user"], source_ip=m["ip"], port=int(m["port"]), raw_line=line,
        )

    if m := _ACCEPTED_RE.match(message):
        return Event(
            timestamp, host, process, EventType.ACCEPTED_LOGIN,
            username=m["user"], source_ip=m["ip"], port=int(m["port"]), raw_line=line,
        )

    if m := _INVALID_RE.match(message):
        port = int(m["port"]) if m["port"] else None
        return Event(
            timestamp, host, process, EventType.INVALID_USER,
            username=m["user"], source_ip=m["ip"], port=port, raw_line=line,
        )

    if (m := _PAM_RE.search(message)) and (fields := _pam_fields(m["fields"])).get("user"):
        # Hedef 'user=' alani dolu olmali; yoksa olay siniflandirilmaz (UNKNOWN'a duser).
        if process == "sudo":
            # sudo'da ilgilendigimiz kisi parolayi yazan AKTORDUR: ruser > logname > user.
            # 'user=' hedef hesaptir; rootpw/targetpw ayarinda 'root' olur ve tum
            # kullanicilari tek hesapta birlestirirdi.
            etype = EventType.SUDO_FAILURE
            username = fields.get("ruser") or fields.get("logname") or fields["user"]
        else:
            # sshd, su vb.: dogrulanmaya calisilan HEDEF hesap.
            etype = EventType.AUTH_FAILURE
            username = fields["user"]
        # rhost dolu ve bos string degilse kaynak IP olarak kullan.
        rhost = fields.get("rhost") or None
        return Event(
            timestamp, host, process, etype,
            username=username, source_ip=rhost, port=None, raw_line=line,
        )

    # Baslik taninip mesaj siniflandirilamadi: bilgiyi kaybetme, UNKNOWN dondur.
    return Event(
        timestamp, host, process, EventType.UNKNOWN,
        username=None, source_ip=None, port=None, raw_line=line,
    )


def parse_lines(
    lines: Iterable[str],
    reference_year: Optional[int] = None,
    now: Optional[datetime] = None,
) -> tuple[list[Event], list[str]]:
    """
    Bir satir akisini parse eder.

    Donus: (events, unparsed_lines)
      - events        : basariyla cozulen Event listesi (UNKNOWN dahil).
      - unparsed_lines: syslog basligi bile eslesmeyen ham satirlar.
    KURAL (spec): eslesmeyen satirlari SESSIZCE YUTMA — listele ve sayisini raporla.
    """
    events: list[Event] = []
    unparsed: list[str] = []
    for line in lines:
        if not line.strip():
            continue  # tamamen bos satirlari sayma
        event = parse_line(line, reference_year=reference_year, now=now)
        if event is None:
            unparsed.append(line.rstrip("\n"))
        else:
            events.append(event)
    return events, unparsed


def parse_file(
    path: str,
    reference_year: Optional[int] = None,
    now: Optional[datetime] = None,
) -> tuple[list[Event], list[str]]:
    """
    Bir auth.log dosyasini okuyup parse eder.

    encoding='utf-8', errors='replace': bozuk baytlarda cokmek yerine devam et
    (gercek log dosyalarinda ara sira bozuk satir olabilir).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, reference_year=reference_year, now=now)
