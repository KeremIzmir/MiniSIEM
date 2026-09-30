"""
su_fail_then_success.py — Ayni (host, aktor, hedef) icin basarisiz su denemelerinin ARDINDAN
util-linux su'nun kaydettigi BASARILI hesap gecisi.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Ayni yerel hesabin ayni hedef hesaba (orn. alice -> root) kisa surede defalarca
basarisiz su denemesi yapip sonunda basariyla gecmesi, parolanin tahmin edilmis olabilecegine
isaret eden yuksek oncelikli bir sinyaldir. Kural bunu kesin saldiri olarak degil, acil
incelenecek bir sinyal olarak raporlar.

BASARI NE DEMEK: SU_SUCCESS, util-linux su'nun "(to hedef) aktor on tty" kaydidir. su bunu
PAM kimlik dogrulama ve hesap kontrolu gectikten SONRA, oturum kurulumundan ONCE yazar. Yani
"basarili gecis kaydedildi" demektir; parolanin girildigini (orn. root icin pam_rootok) ya
da PAM oturumunun kesin acildigini KANITLAMAZ.

NEDEN TAM CIFT (host, aktor, hedef): Aktorun farkli hedefleri taramasini su_brute_force zaten
yakalar. Bu kural daha dar ve daha guvenilir bir soruyu cevaplar: "AYNI gecis once basarisiz
olup sonra basarili oldu mu?" Aktoru ya da hedefi bilinmeyen olay korelasyona girmez.

NEDEN AYRI KURAL: fail_then_success ag kuralidir (kaynak IP, FAILED_PASSWORD/ACCEPTED_LOGIN).
Yerel su'nun kimlik anahtari, olay turleri, aciklamasi ve ayarlari farklidir.

ALGORITMA (fail_then_success ile ayni sozlesme): Her grubun olaylari kararli sekilde zamana
gore siralanir (ayni zaman damgasinda log/girdi sirasi korunur). Basarisizliklar biriktirilir;
bir basari geldiginde basaridan GERIYE 'window' saniye icindeki (KAPSAYICI: fark == window
dahil) basarisizliklar sayilir. Sayi >= min_fails ise alarm. HER basaridan sonra dizi sifirlanir.
Bu "en yogun pencere" degil "basaridan geriye bakis" problemi oldugu icin densest_window
kullanilmaz.

IP ALLOWLIST: Tipik yerel su olaylarinda IP yoktur, etkilenmezler. PAM 'rhost' dolu bir
SU_FAILURE ise mevcut engine on-filtresine tabidir; allowlist o basarisizligi elerse sayim
azalir ve korelasyon kacabilir (yanlis alarm degil, kacan alarm).
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity

_RELEVANT = (EventType.SU_FAILURE, EventType.SU_SUCCESS)


def detect_su_fail_then_success(
    events: list[Event],
    min_fails: int = 3,
    window: int = 600,
) -> list[Alert]:
    """
    'Basarisiz su denemeleri sonra basarili su gecisi' alarmlari uretir.

    Parametreler:
      min_fails : basaridan onceki pencerede gereken min. basarisizlik (varsayilan 3).
      window    : basaridan GERIYE bakilacak sure (saniye, varsayilan 600 = 10 dk).

    Donus: her tetikleyen (host, aktor, hedef, basari ani) icin bir Alert. Severity daima HIGH.
      - count  : penceredeki basarisizlik sayisi (basari dahil DEGIL).
      - kanit  : sayilan son 5 basarisizlik + basari satiri.

    Hata: min_fails 1'den kucukse ya da window negatifse ValueError — olay olmasa bile.
    """
    if min_fails < 1:
        raise ValueError(f"su success min_fails en az 1 olmali: {min_fails}")
    if window < 0:
        raise ValueError(f"su success window negatif olamaz: {window}")

    alerts: list[Alert] = []

    # 1) Yalnizca SU_FAILURE / SU_SUCCESS; aktoru ya da hedefi olmayan olay atlanir.
    groups: dict[tuple[str, str, str], list[Event]] = {}
    for e in events:
        if e.event_type in _RELEVANT and e.actor_username and e.username:
            groups.setdefault((e.host, e.actor_username, e.username), []).append(e)

    for (host, actor, target), group in groups.items():
        # sorted(): cagiranin listesine dokunmaz; kararli -> ayni zamanli olaylar log sirasinda.
        ordered = sorted(group, key=lambda ev: ev.timestamp)

        fail_streak: list[Event] = []
        for e in ordered:
            if e.event_type == EventType.SU_FAILURE:
                fail_streak.append(e)
                continue

            # SU_SUCCESS: yalnizca bu basaridan geriye 'window' icindeki basarisizliklar.
            success_ts = e.timestamp.timestamp()
            recent = [f for f in fail_streak if success_ts - f.timestamp.timestamp() <= window]
            if len(recent) >= min_fails:
                span = int(success_ts - recent[0].timestamp.timestamp())
                start = recent[0].timestamp.strftime("%H:%M:%S")
                end = e.timestamp.strftime("%H:%M:%S")
                alerts.append(
                    Alert(
                        rule_name="su_fail_then_success",
                        severity=Severity.HIGH,
                        source_ip=None,  # yerel islem: kaynak IP yok
                        count=len(recent),
                        time_window=f"{start}-{end} ({span}s)",
                        description=(
                            f"{actor}@{host}: {target} hesabina {span} saniye icinde "
                            f"{len(recent)} basarisiz su denemesinin ardindan basarili su "
                            f"gecisi kaydedildi. Olasi basarili yerel hesap gecisi - acil incele."
                        ),
                        # Kanit: sayilan son 5 basarisizlik + basari satiri (kronolojik).
                        evidence=[ev.raw_line for ev in recent[-5:]] + [e.raw_line],
                    )
                )
            fail_streak = []  # HER basari diziyi sifirlar (alarm uretse de uretmese de)

    return alerts
