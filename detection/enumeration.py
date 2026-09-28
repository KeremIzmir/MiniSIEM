"""
enumeration.py — Kullanici adi taramasi / credential stuffing tespiti.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Brute-force TEK kullaniciya cok parola dener. Enumeration ise tersine
TEK IP'den COK FARKLI kullanici adi dener (admin, oracle, postgres, test, ...).
Bu, "hangi hesaplar var?" diye tarayan ya da sizdirilmis kullanici listesi deneyen
bir saldirganin imzasidir.

OLCUT: Bir IP'nin denedigi BENZERSIZ kullanici adi sayisi. Bunu set ile sayariz;
esik asilirsa alarm. (Sayim degil cesitlilik onemli: 100 kez 'root' denemek
enumeration degil, brute-force'tur.)
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity


def detect_enumeration(
    events: list[Event],
    threshold: int = 5,
) -> list[Alert]:
    """
    Kullanici-enumeration alarmlari uretir.

    Parametre:
      threshold : alarm icin gereken min. FARKLI kullanici adi sayisi (varsayilan 5).

    Donus: esigi asan her IP icin bir Alert.
    """
    if threshold < 1:
        raise ValueError(f"threshold en az 1 olmali: {threshold}")

    alerts: list[Alert] = []

    # Enumeration sinyali olan olay turleri: var olmayan kullanici (INVALID_USER)
    # ve var olmayan kullaniciya parola denemesi de dahil basarisiz girisler.
    relevant = (EventType.INVALID_USER, EventType.FAILED_PASSWORD)

    # IP -> {kullanici adlari} ve IP -> KULLANICI BASINA tek kanit satiri.
    # Kaniti kullaniciya gore anahtarlariz cunku bu kural CESITLILIGI anlatir:
    # sshd tipik olarak ayni deneme icin hem "Invalid user X" hem "Failed password
    # for invalid user X" yazar. Her satiri eklersek 10 satirlik kanit yalnizca 5
    # farkli kullaniciyi gosterir — okuyan kisi cesitliligi goremez.
    users_by_ip: dict[str, set[str]] = {}
    evidence_by_ip: dict[str, dict[str, str]] = {}

    for e in events:
        if e.event_type in relevant and e.source_ip and e.username:
            users_by_ip.setdefault(e.source_ip, set()).add(e.username)
            # setdefault: o kullanici icin GORULEN ILK satiri sakla, sonrakileri atla.
            evidence_by_ip.setdefault(e.source_ip, {}).setdefault(e.username, e.raw_line)

    for ip, users in users_by_ip.items():
        distinct = len(users)
        if distinct >= threshold:
            # Cesitlilik ne kadar yuksekse o kadar suheli.
            if distinct >= threshold * 2:
                sev = Severity.HIGH
            else:
                sev = Severity.MEDIUM

            ornek = ", ".join(sorted(users)[:8])  # kanit ozeti icin ilk birkac kullanici
            alerts.append(
                Alert(
                    rule_name="user_enumeration",
                    severity=sev,
                    source_ip=ip,
                    count=distinct,
                    time_window=None,  # bu kural zaman penceresi degil, cesitlilik bazli
                    description=(
                        f"{ip} adresi {distinct} FARKLI kullanici adi denedi "
                        f"(orn: {ornek}). Olasi hesap taramasi/credential stuffing."
                    ),
                    # Kullanici basina bir satir, en fazla 10 farkli kullanici.
                    evidence=list(evidence_by_ip[ip].values())[:10],
                )
            )

    return alerts
