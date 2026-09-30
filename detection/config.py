"""
config.py — Tespit ayarlarinin kanonik modeli (DetectionConfig).

NEDEN: 14 tespit ayari eskiden motor, CLI ve pano arasinda ayri ayri tanimlanip
aktariliyordu; varsayilanlar birkac yerde tekrar yaziliyordu. Artik varsayilanlarin
TEK kaynagi DEFAULT_DETECTION_CONFIG'tir.

Tasarim kararlari:
  - Salt veri tasiyicidir: DOGRULAMA YAPMAZ. Gecersiz esikler (negatif pencere,
    threshold < 1) bugun oldugu gibi ilgili kural calisirken ayni ValueError ile reddedilir.
  - frozen=True: paylasilan varsayilan nesnesi degistirilemez.
  - allowlist kanonik olarak Optional[tuple[str, ...]]; None ("filtre yok") ile bos tuple
    ayrimi korunur. Sira/tekrar temizlenmez, motor set() ile filtreler.
  - Eski run_detections(...) ve build_store(...) imzalari bugunku 14 ayarda dondurulmus
    uyumluluk adaptorleridir; yeni ayarlar yalnizca bu modele eklenir.

Bagimlilik: yalnizca stdlib (argparse ya da proje modulu import edilmez).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DetectionConfig:
    """Tum tespit kurallarinin ayarlari. Alan sirasi eski run_detections imzasiyla aynidir."""

    window: int = 300                           # brute_force kayan pencere (sn)
    threshold: int = 5                          # brute_force esigi
    enum_threshold: int = 5                     # enumeration: farkli kullanici sayisi
    allowlist: Optional[tuple[str, ...]] = None  # guvenilir IP'ler (tespitten once elenir)
    min_fails: int = 3                          # fail_then_success: min. basarisizlik
    success_window: int = 600                   # fail_then_success: geriye bakma (sn)
    anomaly_k: float = 2.0                      # anomaly: standart sapma katsayisi
    anomaly_min_volume: int = 5                 # anomaly: min. mutlak olay sayisi
    sudo_window: int = 300                      # sudo_brute_force pencere (sn)
    sudo_threshold: int = 3                     # sudo_brute_force esigi
    su_window: int = 300                        # su_brute_force pencere (sn)
    su_threshold: int = 3                       # su_brute_force esigi
    su_success_min_fails: int = 3               # su_fail_then_success: min. basarisizlik
    su_success_window: int = 600                # su_fail_then_success: geriye bakma (sn)


# Varsayilanlarin tek kaynagi: motor, pano ve ortak komut satiri secenekleri buradan okur.
DEFAULT_DETECTION_CONFIG = DetectionConfig()
