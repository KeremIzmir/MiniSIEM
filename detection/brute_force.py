"""
brute_force.py — Tek bir IP'den kisa surede COK basarisiz giris denemesi tespiti.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Bir saldirgan parola deneme-yanilma yapiyorsa, ayni IP'den dakikalar icinde
onlarca "Failed password" gelir. Bunu "kayan zaman penceresi" (sliding window) ile
yakalariz: "herhangi bir 'window' saniyelik aralikta ayni IP'den >= threshold
basarisizlik var mi?"

SLIDING WINDOW: En yogun pencereyi ortak iki isaretcili (two-pointer) secici bulur
(detection/sliding_window.py; ayrintili aciklama orada). Pencere KAPSAYICIDIR ve
esit yogunlukta ILK pencere kazanir. Bu kural o penceredeki olay sayisi
>= threshold ise alarm uretir.
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity
from detection.sliding_window import densest_window


def detect_brute_force(
    events: list[Event],
    window: int = 300,
    threshold: int = 5,
) -> list[Alert]:
    """
    Brute-force alarmlari uretir.

    Parametreler:
      window    : pencere genisligi (saniye). Varsayilan 300 = 5 dakika.
      threshold : pencerede alarm uretmek icin gereken min. basarisizlik sayisi.

    Donus: her tetikleyen IP icin bir Alert.

    Hata: window negatif ya da threshold 1'den kucukse ValueError.
    NEDEN: Bunlar anlamsiz yapilandirmalardir ve sessizce kotu davranirlar —
    negatif pencere two-pointer'i tasirir (IndexError), threshold<=0 ise TEK bir
    olayla bile "high" alarm uretir. Sessiz cop yerine net hata veriyoruz.
    """
    if window < 0:
        raise ValueError(f"window negatif olamaz: {window}")
    if threshold < 1:
        raise ValueError(f"threshold en az 1 olmali: {threshold}")

    alerts: list[Alert] = []

    # 1) Basarisiz PAROLA denemelerini IP'ye gore grupla.
    #    (Sadece FAILED_PASSWORD: 'invalid user' enumeration ayri kuralin isi.)
    by_ip: dict[str, list[Event]] = {}
    for e in events:
        if e.event_type == EventType.FAILED_PASSWORD and e.source_ip:
            by_ip.setdefault(e.source_ip, []).append(e)

    # 2) Her IP icin kayan pencereyi uygula.
    for ip, ip_events in by_ip.items():
        # En yogun pencere (kronolojik); kanit ve sayim bu pencereden gelir.
        window_events = densest_window(ip_events, window)
        best_count = len(window_events)

        # 3) Esik asildiysa alarm uret.
        if best_count >= threshold:
            start = window_events[0].timestamp.strftime("%H:%M:%S")
            end = window_events[-1].timestamp.strftime("%H:%M:%S")
            span = int(window_events[-1].timestamp.timestamp() - window_events[0].timestamp.timestamp())

            # Severity: cok asilirsa daha yuksek. 3x threshold ustu -> high.
            if best_count >= threshold * 3:
                sev = Severity.HIGH
            elif best_count >= threshold * 2:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            alerts.append(
                Alert(
                    rule_name="brute_force",
                    severity=sev,
                    source_ip=ip,
                    count=best_count,
                    time_window=f"{start}-{end} ({span}s)",
                    description=(
                        f"{ip} adresinden {span} saniyede {best_count} basarisiz "
                        f"parola denemesi (esik={threshold}/{window}s)."
                    ),
                    # Kanit olarak en yogun penceredeki ham satirlar (ilk 10 ile sinirli).
                    evidence=[ev.raw_line for ev in window_events[:10]],
                )
            )

    return alerts
