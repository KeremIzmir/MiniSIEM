"""
app.py — Mini SIEM web panosu (Flask, tek sayfa).

Bagimlilik: parser/auth_parser.py, detection/engine.py, storage/store.py.

NEDEN BOYLE: Pano "ince sunum" katmanidir — is mantigi icermez. CLI ile AYNI
akisi kullanir (parse -> store -> run_detections), boylece kurallar tek yerde
(engine) kalir ve iki arayuz arasinda davranis ayrismaz. Pano sadece store'un
verdigi sayilari/alarmlari HTML ve JSON olarak gosterir.

REQUIRES: flask

Calistirma:
    python -m dashboard.app sample_auth.log
    python -m dashboard.app sample_auth.log --host 127.0.0.1 --port 5000

Tasarim kararlari:
  - Log dosyasi acilista BIR KEZ parse edilir ve bellekte tutulur (store).
    Demolik bir SIEM icin yeterli; production'da burasi bir veritabani olurdu.
  - debug=False (varsayilan): spec'teki guvenlik kuralina uygun (production'da
    debug acik birakma). Istege bagli --debug bayragiyla GELISTIRME icin acilir.
  - host varsayilani 127.0.0.1: disa acik 0.0.0.0 bilincli secim olmali, kaza degil.
"""

import argparse
import sys
from typing import Optional

# REQUIRES: flask
try:
    from flask import Flask, jsonify, render_template
except ImportError:  # pragma: no cover
    # Flask kurulu degilse net bir yonerge ver, ImportError yiginini degil.
    print("HATA: Flask kurulu degil. Kurmak icin: pip install flask", file=sys.stderr)
    raise

from parser.auth_parser import parse_file
from storage.store import EventStore
from detection.engine import run_detections

__version__ = "1.0.0"


def build_store(
    logfile: str,
    window: int = 300,
    threshold: int = 5,
    enum_threshold: int = 5,
    allowlist: Optional[list] = None,
    min_fails: int = 3,
    success_window: int = 600,
    anomaly_k: float = 2.0,
    anomaly_min_volume: int = 5,
) -> EventStore:
    """
    Log dosyasini parse edip tum kurallari calistirir ve dolu bir EventStore dondurur.

    CLI'deki ile AYNI akis; ayri tutuyoruz cunku pano bunu acilista bir kez,
    CLI ise her calistirmada cagirir. Mantik (engine) ikisinde de ortak.
    Parametreler CLI ile AYNI yuzeyi sunar — iki arayuz ayni ayarlari kabul etsin.
    """
    events, unparsed = parse_file(logfile)
    store = EventStore()
    store.add_events(events)
    store.unparsed_count = len(unparsed)

    alerts = run_detections(
        events,
        window=window,
        threshold=threshold,
        enum_threshold=enum_threshold,
        allowlist=allowlist,
        min_fails=min_fails,
        success_window=success_window,
        anomaly_k=anomaly_k,
        anomaly_min_volume=anomaly_min_volume,
    )
    for a in alerts:
        store.add_alert(a)
    return store


def create_app(store: EventStore) -> Flask:
    """
    Flask uygulamasini olusturur (application factory deseni).

    store'u disardan aliriz: boylece test ortaminda sahte/kucuk bir store ile
    app yaratip rotalari deneyebiliriz; app dosya okumaya bagli kalmaz.
    """
    app = Flask(__name__)

    @app.route("/")
    def index():
        """Ana pano sayfasi: ozet kartlari, alarmlar, en cok olay ureten IP'ler."""
        return render_template(
            "index.html",
            summary=store.summary(),
            alerts=store.alerts,                 # to_dict() formatinda (template severity.value bekler)
            top_ips=store.top_ips(limit=10),
            timeline=store.failed_per_minute(),  # [(dakika, sayi), ...]
        )

    @app.route("/api/summary")
    def api_summary():
        """Ozet sayilarini JSON olarak ver (harici izleme/entegrasyon icin)."""
        return jsonify(store.summary())

    @app.route("/api/alerts")
    def api_alerts():
        """Tum alarmlari JSON olarak ver."""
        return jsonify(store.alerts)

    @app.route("/api/timeline")
    def api_timeline():
        """Dakika bazinda basarisiz giris zaman serisi (grafik beslemek icin)."""
        # [(label, count)] -> [{"t": label, "count": n}] : JSON'da nesne daha okunur.
        return jsonify([{"t": t, "count": c} for t, c in store.failed_per_minute()])

    return app


def build_arg_parser() -> argparse.ArgumentParser:
    """Komut satiri argumanlari (test edilebilmesi icin ayri)."""
    p = argparse.ArgumentParser(
        prog="mini-siem-dashboard",
        description="Mini SIEM web panosu — auth.log analizini tarayicida gosterir.",
    )
    p.add_argument("logfile", help="Acilista parse edilecek auth.log yolu.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Dinlenecek arayuz. Varsayilan 127.0.0.1 (yerel). Disa acmak icin 0.0.0.0.")
    p.add_argument("--port", type=int, default=5000, help="Dinlenecek port. Varsayilan 5000.")
    p.add_argument("--window", type=int, default=300, help="Brute-force pencere (saniye).")
    p.add_argument("--threshold", type=int, default=5, help="Brute-force esigi.")
    p.add_argument("--enum-threshold", type=int, default=5, help="Enumeration esigi.")
    p.add_argument("--min-fails", type=int, default=3,
                   help="fail_then_success: min. basarisizlik sayisi. Varsayilan 3.")
    p.add_argument("--success-window", type=int, default=600,
                   help="fail_then_success: geriye bakma suresi (saniye). Varsayilan 600.")
    p.add_argument("--anomaly-k", type=float, default=2.0,
                   help="Anomali esigi (standart sapma katsayisi). Varsayilan 2.0.")
    p.add_argument("--anomaly-min-volume", type=int, default=5,
                   help="Anomali icin min. olay sayisi. Varsayilan 5.")
    p.add_argument("--allow", action="append", default=None, metavar="IP",
                   help="Guvenilir IP (tespitten once elenir). Birden cok kez verilebilir.")
    p.add_argument("--debug", action="store_true",
                   help="Flask debug modu (SADECE gelistirme). Varsayilan KAPALI.")
    p.add_argument("--version", action="version", version=f"mini-siem-dashboard {__version__}")
    return p


def main() -> None:
    """Konsol giris noktasi: dosyayi isle, app'i kur, sunucuyu baslat."""
    args = build_arg_parser().parse_args()

    try:
        store = build_store(
            args.logfile,
            window=args.window,
            threshold=args.threshold,
            enum_threshold=args.enum_threshold,
            allowlist=args.allow,
            min_fails=args.min_fails,
            success_window=args.success_window,
            anomaly_k=args.anomaly_k,
            anomaly_min_volume=args.anomaly_min_volume,
        )
    except FileNotFoundError:
        print(f"HATA: dosya bulunamadi: {args.logfile}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        # Dizin verilmesi, izin hatasi, bozuk cihaz... CLI bunlari zaten yakaliyordu;
        # pano da traceback yerine net mesaj versin (iki arayuz ayni davransin).
        print(f"HATA: dosya okunamadi: {exc}", file=sys.stderr)
        sys.exit(2)
    except ValueError as exc:
        print(f"HATA: gecersiz tespit ayari: {exc}", file=sys.stderr)
        sys.exit(2)

    app = create_app(store)
    s = store.summary()
    print(f"Mini SIEM panosu: http://{args.host}:{args.port}  "
          f"({s['toplam_olay']} olay, {s['alarm_sayisi']} alarm)")
    # debug args.debug ile kontrol edilir; varsayilan False -> production'da acik kalmaz.
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
