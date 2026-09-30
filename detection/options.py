"""
options.py — CLI ve panonun ORTAK tespit komut satiri secenekleri.

NEDEN: 14 tespit bayragi eskiden cli.py ve dashboard/app.py'de ayri ayri tanimlaniyordu;
varsayilanlar ve aciklamalar kayabiliyordu. Artik iki arayuz de bayraklari buradan alir,
varsayilanlar DEFAULT_DETECTION_CONFIG'ten okunur.

Kapsam: YALNIZCA tespit ayarlari. Arayuze ozgu bayraklar (--json, --quiet, --no-color,
--host, --port, --debug, --version) kendi parser'larinda kalir.

Bagimlilik: argparse + detection/config.py. Motoru (engine) import ETMEZ; boylece
config modeli argparse'tan, bu modul de tespit mantigindan bagimsiz kalir.
"""

import argparse

from detection.config import DEFAULT_DETECTION_CONFIG, DetectionConfig

_D = DEFAULT_DETECTION_CONFIG


def add_detection_arguments(parser: argparse.ArgumentParser) -> None:
    """14 tespit bayragini parser'a bugunku sira, tip, varsayilan ve action ile ekler."""
    parser.add_argument("--window", type=int, default=_D.window,
                        help=f"Brute-force kayan pencere genisligi (saniye). Varsayilan {_D.window}.")
    parser.add_argument("--threshold", type=int, default=_D.threshold,
                        help="Brute-force esigi (pencere icindeki basarisiz deneme). "
                             f"Varsayilan {_D.threshold}.")
    parser.add_argument("--enum-threshold", type=int, default=_D.enum_threshold,
                        help="Enumeration esigi (bir IP'nin denedigi farkli kullanici sayisi). "
                             f"Varsayilan {_D.enum_threshold}.")
    parser.add_argument("--min-fails", type=int, default=_D.min_fails,
                        help="fail_then_success: basariyi suheli yapan min. basarisizlik. "
                             f"Varsayilan {_D.min_fails}.")
    parser.add_argument("--success-window", type=int, default=_D.success_window,
                        help="fail_then_success: basaridan geriye bakma suresi (saniye). "
                             f"Varsayilan {_D.success_window}.")
    parser.add_argument("--anomaly-k", type=float, default=_D.anomaly_k,
                        help="Anomali esigi: kac standart sapma ustu aykiri sayilsin "
                             f"(negatif olmayan sonlu sayi). Varsayilan {_D.anomaly_k}.")
    parser.add_argument("--anomaly-min-volume", type=int, default=_D.anomaly_min_volume,
                        help="Anomali icin gereken min. mutlak olay sayisi (en az 1). "
                             f"Varsayilan {_D.anomaly_min_volume}.")
    parser.add_argument("--sudo-window", type=int, default=_D.sudo_window,
                        help="sudo_brute_force: ayni host+kullanici basarisiz sudo penceresi (saniye). "
                             f"Varsayilan {_D.sudo_window}.")
    parser.add_argument("--sudo-threshold", type=int, default=_D.sudo_threshold,
                        help="sudo_brute_force: pencerede alarm icin min. basarisiz sudo sayisi. "
                             f"Varsayilan {_D.sudo_threshold}.")
    parser.add_argument("--su-window", type=int, default=_D.su_window,
                        help="su_brute_force: ayni host+aktor basarisiz su penceresi (saniye). "
                             f"Varsayilan {_D.su_window}.")
    parser.add_argument("--su-threshold", type=int, default=_D.su_threshold,
                        help="su_brute_force: pencerede alarm icin min. basarisiz su sayisi. "
                             f"Varsayilan {_D.su_threshold}.")
    parser.add_argument("--su-success-min-fails", type=int, default=_D.su_success_min_fails,
                        help="su_fail_then_success: basarili su gecisinden onceki min. basarisiz su "
                             f"(ayni host+aktor+hedef). Varsayilan {_D.su_success_min_fails}.")
    parser.add_argument("--su-success-window", type=int, default=_D.su_success_window,
                        help="su_fail_then_success: basaridan geriye bakma suresi (saniye). "
                             f"Varsayilan {_D.su_success_window}.")
    # default=None (liste degil): hic verilmezse "filtre yok" anlami korunur.
    parser.add_argument("--allow", action="append", default=None, metavar="IP",
                        help="Guvenilir IP (tespitten once elenir). Birden cok kez verilebilir. "
                             "Yalnizca kaynak IP'si olan olaylari etkiler; yerel sudo/su alarmlarini bastirmaz.")


def detection_config_from_namespace(args: argparse.Namespace) -> DetectionConfig:
    """
    add_detection_arguments ile uretilen bayraklari ACIKCA DetectionConfig'e tasir.

    --allow listesi tuple'a cevrilir; sira ve tekrarlar korunur, verilmediyse None kalir.
    Dogrulama yapilmaz (kurallar yapar).
    """
    return DetectionConfig(
        window=args.window,
        threshold=args.threshold,
        enum_threshold=args.enum_threshold,
        allowlist=None if args.allow is None else tuple(args.allow),
        min_fails=args.min_fails,
        success_window=args.success_window,
        anomaly_k=args.anomaly_k,
        anomaly_min_volume=args.anomaly_min_volume,
        sudo_window=args.sudo_window,
        sudo_threshold=args.sudo_threshold,
        su_window=args.su_window,
        su_threshold=args.su_threshold,
        su_success_min_fails=args.su_success_min_fails,
        su_success_window=args.su_success_window,
    )
