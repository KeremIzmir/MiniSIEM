"""
engine.py — Tum tespit kurallarini tek noktadan calistiran motor.

Bagimlilik: dort kural modulu + Event/Alert/Severity.

NEDEN BOYLE: CLI ve dashboard, hangi kurallarin oldugunu bilmek zorunda kalmasin.
Ikisi de sadece run_detections(events) cagirir; yeni kural eklemek = burada bir
satir eklemek. Is mantigi tek yerde toplanir (dashboard onu tekrarlamaz).

Bu dosya, qwen3-coder:30b tarafindan uretilen mantigin uzerine modul docstring'i
ve aciklayici yorumlar eklenmis halidir (ham cikti: logs/ollama_outputs/engine.py.raw).
"""

from typing import List, Optional

from parser.events import Event
from detection.alert import Alert, Severity
from detection.brute_force import detect_brute_force
from detection.enumeration import detect_enumeration
from detection.fail_then_success import detect_fail_then_success
from detection.anomaly import detect_anomalous_ips


def run_detections(
    events: List[Event],
    window: int = 300,
    threshold: int = 5,
    enum_threshold: int = 5,
    allowlist: Optional[List[str]] = None,
) -> List[Alert]:
    """
    Tum tespit kurallarini calistirir ve alarmlari severity + count'a gore siralar.

    Parametreler:
        events        : islenecek olay listesi.
        window        : brute-force kayan pencere genisligi (saniye).
        threshold     : brute-force esigi.
        enum_threshold: enumeration esigi (farkli kullanici sayisi).
        allowlist     : guvenilir IP'ler. Bu IP'lerden gelen olaylar tespitten
                        ONCE elenir (guvenilir kaynaklar yanlis alarm uretmesin).

    Donus: severity.rank'a gore AZALAN (high once), esitlikte count'a gore azalan
           sirali Alert listesi.
    """
    # Allowlist tespitten ONCE uygulanir: boylece guvenilir IP hicbir kuralda
    # sayilmaz (yoksa her kuralda ayri ayri filtrelemek gerekirdi -> tekrar/hata riski).
    if allowlist is not None:
        allow = set(allowlist)  # 'in' kontrolu set'te O(1)
        filtered_events = [e for e in events if e.source_ip not in allow]
    else:
        filtered_events = events

    # Tum kurallari calistir, alarmlari tek listede topla.
    alerts: List[Alert] = []
    alerts.extend(detect_brute_force(filtered_events, window=window, threshold=threshold))
    alerts.extend(detect_enumeration(filtered_events, threshold=enum_threshold))
    alerts.extend(detect_fail_then_success(filtered_events))
    alerts.extend(detect_anomalous_ips(filtered_events))

    # Severity.rank ile siralama: alfabetik string sirasi yanlis olurdu
    # ("high" < "low"), bu yuzden sayisal rank kullaniriz. Negatif -> azalan.
    alerts.sort(key=lambda a: (-a.severity.rank, -a.count))
    return alerts
