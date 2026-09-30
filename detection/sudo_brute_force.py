"""
sudo_brute_force.py — Ayni host'ta ayni kullanicinin kisa surede TEKRARLANAN basarisiz sudo denemeleri.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Tek bir basarisiz sudo kimlik dogrulamasi siradan bir yazim hatasi olabilir. Ama
ayni yerel hesap kisa surede tekrar tekrar basarisiz oluyorsa bu, daha degerli bir
guvenlik sinyalidir: olasi bir yerel yetki yukseltme ya da parola tahmin (credential
guessing) denemesine isaret edebilir. Kural bunu kesin saldiri olarak degil, incelenecek
bir sinyal olarak raporlar.

NEDEN AYRI KURAL: Diger kurallarin hepsi olaylari KAYNAK IP'ye gore gruplar. sudo yerel
bir islemdir; SUDO_FAILURE olaylarinda IP yoktur (rhost bos). Bu yuzden anahtar
(host, username) olur: farkli makinelerdeki ayni isim ya da ayni makinedeki farkli
kullanicilar asla birlestirilmez.

ALGORITMA: En yogun pencereyi ortak iki isaretcili (two-pointer) secici bulur
(detection/sliding_window.py; ayrintili aciklama orada). Pencere KAPSAYICIDIR: iki olay
arasindaki fark tam 'window' saniye ise ayni penceredeler. Esit yogunlukta ILK pencere
kazanir.

IP ALLOWLIST: Engine'in --allow filtresi source_ip'e bakar; sudo olaylarinda IP
olmadigi icin bu kural allowlist'ten etkilenmez. Bu bilinclidir: bir ag adresine
guvenmek, o makinedeki yerel hesaplarin sudo denemelerine guvenmek demek degildir.
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity
from detection.sliding_window import densest_window


def detect_sudo_brute_force(
    events: list[Event],
    window: int = 300,
    threshold: int = 3,
) -> list[Alert]:
    """
    Tekrarlanan basarisiz sudo kimlik dogrulamasi alarmlari uretir.

    Parametreler:
      window    : pencere genisligi (saniye). Varsayilan 300 = 5 dakika.
      threshold : pencerede alarm icin gereken min. basarisizlik. Varsayilan 3: MiniSIEM'in
                  sectigi proje varsayilanidir (tek bir yazim hatasi alarm uretmesin diye);
                  platformdan platforma degisebilen sudo ayarlarini yansitmaz, gerekirse
                  --sudo-threshold ile ayarlanir.

    Donus: her tetikleyen (host, username) icin EN FAZLA bir Alert (en yogun pencereden).

    Severity: threshold <= sayi < 2*threshold -> MEDIUM, sayi >= 2*threshold -> HIGH.
    LOW yok: esik zaten tekil yazim hatalarini eler; esige ulasan tekrarli sudo hatalari,
    yetkili komut calistirma baglaminda oldugu icin en az MEDIUM onem tasir.

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

    # 2) Her grup icin en yogun kayan pencere (ortak secici girdi sirasina guvenmez).
    for (host, user), group in groups.items():
        # En yogun kapsayici pencere (kronolojik); kanit ve sayim bu pencereden gelir.
        window_events = densest_window(group, window)
        best_count = len(window_events)

        # 3) Esik asildiysa grup basina tek alarm.
        if best_count >= threshold:
            start = window_events[0].timestamp.strftime("%H:%M:%S")
            end = window_events[-1].timestamp.strftime("%H:%M:%S")
            span = int(window_events[-1].timestamp.timestamp() - window_events[0].timestamp.timestamp())
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
