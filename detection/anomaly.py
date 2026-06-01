"""
anomaly.py — Istatistiksel aykiri-deger (outlier) ile anormal IP tespiti.

Bagimlilik: parser/events.py, detection/alert.py, stdlib(ipaddress, statistics).

FIKIR: Onceki kurallar sabit esikler kullanir (orn. >=5 deneme). Ama "normal"
trafik her ortamda farklidir. Burada esigi VERIYE gore belirleriz: her IP'nin
deneme hacmini bakar, ortalamadan COK sapan IP'leri flag'leriz.

NEDEN Z-SCORE (ortalama + k*stddev)?
  - Hesabi basit ve sezgisel: "ortalamadan k standart sapma uzakta mi?"
  - Ogretici: istatistigin temel araci, anlatmasi kolay.
  - Sinirlamasi: kucuk orneklemde ve agir-kuyruklu dagilimda yaniltici olabilir
    (cunku ortalama ve stddev'in kendisi aykiri degerlerden etkilenir). Gercek
    SIEM'de medyan + IQR (ceyrekler arasi acoklik) daha saglam (robust) olurdu;
    ama bu ogrenme projesinde z-score'u tercih ettik. IQR'a gecmek istersen:
    Q1, Q3 hesapla; ust sinir = Q3 + 1.5*(Q3-Q1).

EK OLCUTLER (alarm aciklamasina baglam katar):
  - failed/total orani: IP'nin ne kadari basarisiz.
  - hedef kullanici cesitliligi: kac farkli kullanici denenmis.
"""

import ipaddress
import statistics
from parser.events import Event
from detection.alert import Alert, Severity


def is_public_ip(ip: str) -> bool:
    """
    IP public (internetten) mi, private/yerel mi? Gecersiz string'lerde False doner
    (parse edilemeyeni 'public gibi davranma', sessizce ele). Ic ag IP'leri (10.x,
    192.168.x, 172.16-31.x) genelde daha az suhelidir.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def detect_anomalous_ips(
    events: list[Event],
    k: float = 2.0,
    min_volume: int = 5,
) -> list[Alert]:
    """
    Hacim olarak aykiri (anormal) IP'leri uretir.

    Parametreler:
      k          : kac standart sapma ustu 'anormal' sayilsin (varsayilan 2.0).
      min_volume : alarm icin gereken min. mutlak deneme sayisi. Z-score yuksek olsa
                   bile cok kucuk hacmi (orn 2 deneme) flag'lemeyelim diye guvenlik freni.

    Donus: aykiri her IP icin bir Alert.
    """
    alerts: list[Alert] = []

    # 1) IP basina sayac: toplam, basarisiz, denenen kullanicilar.
    total: dict[str, int] = {}
    failed: dict[str, int] = {}
    users: dict[str, set[str]] = {}
    for e in events:
        ip = e.source_ip
        if not ip:
            continue
        total[ip] = total.get(ip, 0) + 1
        if e.is_failure:
            failed[ip] = failed.get(ip, 0) + 1
        if e.username:
            users.setdefault(ip, set()).add(e.username)

    if len(total) < 2:
        return alerts  # istatistik icin en az 2 IP lazim (stddev tanimsiz olur)

    volumes = list(total.values())
    mean = statistics.mean(volumes)
    # pstdev: anakitle standart sapmasi (elimizdeki tum IP'ler 'populasyon'). n=1 ise 0 doner.
    stdev = statistics.pstdev(volumes)
    cutoff = mean + k * stdev  # bu hacmin USTU = aykiri

    for ip, vol in total.items():
        if vol >= min_volume and stdev > 0 and vol > cutoff:
            fcount = failed.get(ip, 0)
            ratio = fcount / vol if vol else 0.0
            ucount = len(users.get(ip, set()))

            # Basarisizlik orani yuksekse daha suheli.
            sev = Severity.HIGH if ratio >= 0.8 else Severity.MEDIUM

            alerts.append(
                Alert(
                    rule_name="anomalous_ip",
                    severity=sev,
                    source_ip=ip,
                    count=vol,
                    time_window=None,
                    description=(
                        f"{ip} anormal hacim: {vol} olay "
                        f"(ortalama={mean:.1f}, esik=ort+{k}*std={cutoff:.1f}). "
                        f"Basarisiz oran={ratio:.0%}, {ucount} farkli kullanici, "
                        f"{'public' if is_public_ip(ip) else 'private'} IP."
                    ),
                    evidence=[],  # bu kural istatistik ozeti; ham satir yerine sayilar konusur
                )
            )

    return alerts
