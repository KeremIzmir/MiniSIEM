"""
sudo_brute_force.py — Ayni host'ta ayni kullanicinin kisa surede TEKRARLANAN basarisiz sudo denemeleri.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Tek bir yanlis sudo parolasi siradan bir yazim hatasidir. Ama ayni yerel hesap
dakikalar icinde tekrar tekrar basarisiz oluyorsa bu, ele gecirilmis bir oturumdan
root parolasini tahmin etme (yerel yetki yukseltme) denemesi olabilir.

NEDEN AYRI KURAL: Diger kurallarin hepsi olaylari KAYNAK IP'ye gore gruplar. sudo yerel
bir islemdir; SUDO_FAILURE olaylarinda IP yoktur (rhost bos). Bu yuzden anahtar
(host, username) olur: farkli makinelerdeki ayni isim ya da ayni makinedeki farkli
kullanicilar asla birlestirilmez.

ALGORITMA: brute_force.py ile ayni iki isaretcili kayan pencere (ayrintili aciklama
orada). Pencere KAPSAYICIDIR: iki olay arasindaki fark tam 'window' saniye ise ayni
penceredeler. Ortak bir yardimciya bilincli olarak cikarilmadi — iki kucuk kuralda
benzer bir dongu, calisan brute_force kuralini degistirmekten daha guvenli.

IP ALLOWLIST: Engine'in --allow filtresi source_ip'e bakar; sudo olaylarinda IP
olmadigi icin bu kural allowlist'ten etkilenmez. Bu bilinclidir: bir ag adresine
guvenmek, o makinedeki yerel hesaplarin sudo denemelerine guvenmek demek degildir.
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity


def detect_sudo_brute_force(
    events: list[Event],
    window: int = 300,
    threshold: int = 3,
) -> list[Alert]:
    """
    Tekrarlanan basarisiz sudo kimlik dogrulamasi alarmlari uretir.

    Parametreler:
      window    : pencere genisligi (saniye). Varsayilan 300 = 5 dakika.
      threshold : pencerede alarm icin gereken min. basarisizlik. Varsayilan 3
                  (sudo'nun varsayilan deneme hakki; tek yazim hatasi alarm uretmez).

    Donus: her tetikleyen (host, username) icin EN FAZLA bir Alert (en yogun pencereden).

    Severity: threshold <= sayi < 2*threshold -> MEDIUM, sayi >= 2*threshold -> HIGH.
    LOW yok: esige ulasmak zaten deneme hakkini tuketmek demektir ve hedef root'tur.

    Hata: window negatif ya da threshold 1'den kucukse ValueError — olay olmasa bile
    (dogrulama filtrelemeden ONCE yapilir; gecersiz ayar sessizce kabul edilmesin).
    """
    if window < 0:
        raise ValueError(f"sudo window negatif olamaz: {window}")
    if threshold < 1:
        raise ValueError(f"sudo threshold en az 1 olmali: {threshold}")

    alerts: list[Alert] = []

    # 1) Yalnizca SUDO_FAILURE; kime ait oldugu bilinmeyen (username yok) olay atlanir.
    groups: dict[tuple[str, str], list[Event]] = {}
    for e in events:
        if e.event_type == EventType.SUDO_FAILURE and e.username:
            groups.setdefault((e.host, e.username), []).append(e)

    # 2) Her grup icin kayan pencere (girdi sirasina guvenmeyiz -> once sirala).
    for (host, user), group in groups.items():
        group.sort(key=lambda ev: ev.timestamp)
        times = [ev.timestamp.timestamp() for ev in group]

        left = 0
        best_count = 0
        best_left = best_right = 0  # en yogun pencerenin sinirlari (kanit icin)

        for right in range(len(times)):
            # '> window' iken daralt: fark tam 'window' ise olay pencerede kalir (kapsayici).
            while left < right and times[right] - times[left] > window:
                left += 1
            current = right - left + 1
            if current > best_count:
                best_count = current
                best_left, best_right = left, right

        # 3) Esik asildiysa grup basina tek alarm.
        if best_count >= threshold:
            window_events = group[best_left : best_right + 1]
            start = window_events[0].timestamp.strftime("%H:%M:%S")
            end = window_events[-1].timestamp.strftime("%H:%M:%S")
            span = int(times[best_right] - times[best_left])
            sev = Severity.HIGH if best_count >= threshold * 2 else Severity.MEDIUM

            alerts.append(
                Alert(
                    rule_name="sudo_brute_force",
                    severity=sev,
                    source_ip=None,  # yerel islem: kaynak IP yok
                    count=best_count,
                    time_window=f"{start}-{end} ({span}s)",
                    description=(
                        f"{user}@{host}: {span} saniyede {best_count} basarisiz sudo "
                        f"kimlik dogrulamasi (esik={threshold}/{window}s). "
                        f"Olasi yerel yetki yukseltme veya parola tahmin denemesi."
                    ),
                    # Kanit: en yogun penceredeki ham satirlar, kronolojik, en fazla 10.
                    evidence=[ev.raw_line for ev in window_events[:10]],
                )
            )

    return alerts
