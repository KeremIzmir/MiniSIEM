"""
engine.py — Tum tespit kurallarini tek noktadan calistiran motor.

Bagimlilik: tum kural modulleri + Event/Alert/Severity.

NEDEN BOYLE: CLI ve dashboard, hangi kurallarin oldugunu bilmek zorunda kalmasin.
Ikisi de run_detections_with_config(events, config) cagirir; yeni kural eklemek =
burada bir satir eklemek. Ayarlar detection/config.py'deki DetectionConfig'te durur.
Is mantigi tek yerde toplanir (dashboard onu tekrarlamaz).

Bu dosya, qwen3-coder:30b tarafindan uretilen mantigin uzerine modul docstring'i
ve aciklayici yorumlar eklenmis halidir (ham cikti: logs/ollama_outputs/engine.py.raw).
"""

from typing import List, Optional

from parser.events import Event
from detection.alert import Alert, Severity
from detection.config import DEFAULT_DETECTION_CONFIG, DetectionConfig
from detection.brute_force import detect_brute_force
from detection.enumeration import detect_enumeration
from detection.fail_then_success import detect_fail_then_success
from detection.anomaly import detect_anomalous_ips
from detection.sudo_brute_force import detect_sudo_brute_force
from detection.su_brute_force import detect_su_brute_force
from detection.su_fail_then_success import detect_su_fail_then_success


def run_detections_with_config(events: List[Event], config: DetectionConfig) -> List[Alert]:
    """
    Tum tespit kurallarini DetectionConfig ile calistirir ve alarmlari severity + count'a
    gore siralar. Kanonik (config tabanli) yol: CLI ve pano bunu kullanir.

    Ayarlarin anlamlari icin detection/config.py'ye bakin. Dogrulama config'te DEGIL,
    her kuralin kendisinde yapilir; gecersiz esikler ilgili kural calisirken ValueError verir.

    allowlist: guvenilir IP'ler. Bu IP'lerden gelen olaylar tespitten ONCE elenir
    (guvenilir kaynaklar yanlis alarm uretmesin). Yalnizca kaynak IP'si olan (ag kaynakli)
    olaylari etkiler; tipik yerel sudo/su olaylarinda IP yoktur, bu yuzden elenmezler
    (IP'si gercekten dolu bir olay ise bu filtreye tabidir).

    Donus: severity.rank'a gore AZALAN (high once), esitlikte count'a gore azalan
           sirali Alert listesi.
    """
    # Allowlist tespitten ONCE uygulanir: boylece guvenilir IP hicbir kuralda
    # sayilmaz (yoksa her kuralda ayri ayri filtrelemek gerekirdi -> tekrar/hata riski).
    if config.allowlist is not None:
        allow = set(config.allowlist)  # 'in' kontrolu set'te O(1)
        filtered_events = [e for e in events if e.source_ip not in allow]
    else:
        filtered_events = events

    # Tum kurallari calistir, alarmlari tek listede topla.
    alerts: List[Alert] = []
    alerts.extend(detect_brute_force(filtered_events, window=config.window, threshold=config.threshold))
    alerts.extend(detect_enumeration(filtered_events, threshold=config.enum_threshold))
    alerts.extend(detect_fail_then_success(
        filtered_events, min_fails=config.min_fails, window=config.success_window))
    alerts.extend(detect_anomalous_ips(
        filtered_events, k=config.anomaly_k, min_volume=config.anomaly_min_volume))
    alerts.extend(detect_sudo_brute_force(
        filtered_events, window=config.sudo_window, threshold=config.sudo_threshold))
    alerts.extend(detect_su_brute_force(
        filtered_events, window=config.su_window, threshold=config.su_threshold))
    alerts.extend(detect_su_fail_then_success(
        filtered_events, min_fails=config.su_success_min_fails, window=config.su_success_window))

    # Severity.rank ile siralama: alfabetik string sirasi yanlis olurdu
    # ("high" < "low"), bu yuzden sayisal rank kullaniriz. Negatif -> azalan.
    alerts.sort(key=lambda a: (-a.severity.rank, -a.count))
    return alerts


# Eski imzanin varsayilanlari kanonik kaynaktan okunur (literal tekrari yok).
_D = DEFAULT_DETECTION_CONFIG


def run_detections(
    events: List[Event],
    window: int = _D.window,
    threshold: int = _D.threshold,
    enum_threshold: int = _D.enum_threshold,
    allowlist: Optional[List[str]] = _D.allowlist,
    min_fails: int = _D.min_fails,
    success_window: int = _D.success_window,
    anomaly_k: float = _D.anomaly_k,
    anomaly_min_volume: int = _D.anomaly_min_volume,
    sudo_window: int = _D.sudo_window,
    sudo_threshold: int = _D.sudo_threshold,
    su_window: int = _D.su_window,
    su_threshold: int = _D.su_threshold,
    su_success_min_fails: int = _D.su_success_min_fails,
    su_success_window: int = _D.su_success_window,
) -> List[Alert]:
    """
    Uyumluluk adaptoru: mevcut cagrilar (keyword ve positional) aynen calissin diye
    bugunku 14 ayarlik imza korunur. Yalnizca DetectionConfig kurar ve
    run_detections_with_config'e devreder; kendi davranis mantigi yoktur.

    Bu imza DONDURULMUSTUR: ileride eklenecek ayarlar yalnizca DetectionConfig ve
    run_detections_with_config uzerinden sunulur. Deprecated DEGILDIR.
    """
    config = DetectionConfig(
        window=window,
        threshold=threshold,
        enum_threshold=enum_threshold,
        allowlist=None if allowlist is None else tuple(allowlist),
        min_fails=min_fails,
        success_window=success_window,
        anomaly_k=anomaly_k,
        anomaly_min_volume=anomaly_min_volume,
        sudo_window=sudo_window,
        sudo_threshold=sudo_threshold,
        su_window=su_window,
        su_threshold=su_threshold,
        su_success_min_fails=su_success_min_fails,
        su_success_window=su_success_window,
    )
    return run_detections_with_config(events, config)
