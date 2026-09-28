"""
cli.py — Mini SIEM komut satiri arayuzu.

Bagimlilik: parser/auth_parser.py, detection/engine.py, storage/store.py.

NEDEN BOYLE: cli.py "ince" bir katman olmali — is mantigi tasimaz, sadece
parcalari birbirine baglar: dosyayi parse et -> depoya koy -> kurallari calistir
-> sonucu yazdir. Ayni akisi dashboard da kullanir; mantik engine/store'da
toplandigi icin burada tekrar edilmez.

Kullanim:
    python cli.py sample_auth.log
    python cli.py sample_auth.log --json rapor.json
    python cli.py sample_auth.log --window 300 --threshold 5 --allow 198.51.100.5
    python cli.py sample_auth.log --quiet        # sadece alarmlari goster
"""

import argparse
import re
import sys
from typing import List, Optional

from parser.auth_parser import parse_file
from storage.store import EventStore
from detection.engine import run_detections
from detection.alert import Alert

__version__ = "1.0.0"


# Log satirlarindaki KONTROL KARAKTERLERI (C0/C1 + DEL).
# NEDEN: Bir SIEM'in isledigi log satirlari saldirgan kontrolundedir — SSH'a
# "Invalid user <ESC>[2J" gibi bir kullanici adiyla baglanmak yeterlidir. Bu ham
# satiri kanit olarak dogrudan terminale basarsak saldirganin ANSI kacis dizileri
# analistin ekraninda CALISIR: ekrani temizleyebilir, pencere basligini
# degistirebilir, hatta onceki alarm satirlarini sahte metinle uzerine yazabilir.
# Bu yuzden gosterimden HEMEN once kacislari zararsiz hale getiriyoruz (CWE-117).
# Sekme haric tum C0 (0x00-0x1F), DEL (0x7F) ve C1 (0x80-0x9F) araligi.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(text: str) -> str:
    """
    Kontrol karakterlerini gorunur bir yer tutucuyla degistirir.

    Silmek yerine isaretliyoruz (\\xNN): kanitin bozuldugu belli olsun, analist
    satirda gizli bayt oldugunu GORSUN. Ham hali --json ciktisinda korunur
    (json.dumps kacislari zaten \\u001b olarak guvenle kodlar).
    """
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


# ANSI renkleri: terminal destekliyorsa alarmlari severity'ye gore renklendir.
# Renk SADECE gosterim icindir; --json ciktisina asla karismaz (orada ham veri).
_COLORS = {
    "high": "\033[91m",     # kirmizi
    "medium": "\033[93m",   # sari
    "low": "\033[96m",      # cyan
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _supports_color(stream) -> bool:
    """
    Cikti bir gercek terminale mi gidiyor? Dosyaya/pipe'a yonlendirildiyse
    (orn '> out.txt') ANSI kodlari cirkin gorunur — o zaman renksiz yazariz.
    """
    return hasattr(stream, "isatty") and stream.isatty()


def _color(text: str, key: str, enabled: bool) -> str:
    """enabled True ise metni ANSI koduyla sarar; degilse oldugu gibi dondurur."""
    if not enabled:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def _print_summary(store: EventStore, color: bool, out) -> None:
    """Ust ozet kartlari: toplam olay, basarisiz giris, benzersiz IP, alarm, unparsed."""
    s = store.summary()
    print(_color("=== OZET ===", "bold", color), file=out)
    print(f"  Toplam olay      : {s['toplam_olay']}", file=out)
    print(f"  Basarisiz giris  : {s['basarisiz_giris']}", file=out)
    print(f"  Benzersiz IP     : {s['benzersiz_ip']}", file=out)
    print(f"  Uretilen alarm   : {s['alarm_sayisi']}", file=out)
    if s["unparsed"]:
        # Eslesmeyen satirlari SESSIZCE yutma (spec): sayisini acikca bildir.
        print(_color(f"  Parse edilemeyen : {s['unparsed']} satir", "medium", color), file=out)


def _print_top_ips(store: EventStore, out, limit: int = 5) -> None:
    """En cok olay ureten IP'ler tablosu (kucuk, hizli bakis)."""
    rows = store.top_ips(limit=limit)
    if not rows:
        return
    print("\n=== EN COK OLAY URETEN IP'LER ===", file=out)
    for ip, count in rows:
        # IP alani regex'te \S+ oldugu icin log'dan gelen her sey olabilir -> temizle.
        print(f"  {_safe(ip):<18} {count} olay", file=out)


def _print_alerts(alerts: List[Alert], color: bool, out) -> None:
    """Alarmlari severity (yuksek once) sirali, kanitlariyla birlikte yazar."""
    if not alerts:
        print(_color("\nAlarm yok — temiz gorunuyor.", "low", color), file=out)
        return

    print(_color(f"\n=== ALARMLAR ({len(alerts)}) ===", "bold", color), file=out)
    for a in alerts:
        sev = a.severity.value
        head = f"[{sev.upper():^6}] {a.rule_name}"
        print(_color(head, sev, color), file=out)
        if a.source_ip:
            print(f"    IP        : {_safe(a.source_ip)}", file=out)
        print(f"    Olay sayisi: {a.count}", file=out)
        if a.time_window:
            print(f"    Zaman     : {a.time_window}", file=out)
        # Aciklama da log'dan gelen kullanici adi/IP icerebilir -> temizle.
        print(f"    Aciklama  : {_safe(a.description)}", file=out)
        if a.evidence:
            # Kanit satirlarini soluk renkle, en fazla 3 tane goster (taban gurultu olmasin).
            print("    Kanit     :", file=out)
            for line in a.evidence[:3]:
                print(_color(f"      | {_safe(line)}", "dim", color), file=out)
            if len(a.evidence) > 3:
                print(_color(f"      | ... (+{len(a.evidence) - 3} satir daha)", "dim", color), file=out)
        print("", file=out)


def build_parser() -> argparse.ArgumentParser:
    """Komut satiri argumanlarini tanimlar (test edilebilmesi icin ayri fonksiyon)."""
    p = argparse.ArgumentParser(
        prog="mini-siem",
        description="Mini SIEM — auth.log icinden guvenlik olaylarini cikarir ve alarm uretir.",
    )
    p.add_argument("logfile", help="Islenecek auth.log dosyasinin yolu.")
    p.add_argument("--json", metavar="PATH", default=None,
                   help="Tum sonucu (ozet+olaylar+alarmlar) bu JSON dosyasina yaz.")
    p.add_argument("--window", type=int, default=300,
                   help="Brute-force kayan pencere genisligi (saniye). Varsayilan 300.")
    p.add_argument("--threshold", type=int, default=5,
                   help="Brute-force esigi (pencere icindeki basarisiz deneme). Varsayilan 5.")
    p.add_argument("--enum-threshold", type=int, default=5,
                   help="Enumeration esigi (bir IP'nin denedigi farkli kullanici sayisi). Varsayilan 5.")
    p.add_argument("--min-fails", type=int, default=3,
                   help="fail_then_success: basariyi suheli yapan min. basarisizlik. Varsayilan 3.")
    p.add_argument("--success-window", type=int, default=600,
                   help="fail_then_success: basaridan geriye bakma suresi (saniye). Varsayilan 600.")
    p.add_argument("--anomaly-k", type=float, default=2.0,
                   help="Anomali esigi: kac standart sapma ustu aykiri sayilsin. Varsayilan 2.0.")
    p.add_argument("--anomaly-min-volume", type=int, default=5,
                   help="Anomali icin gereken min. mutlak olay sayisi. Varsayilan 5.")
    p.add_argument("--allow", action="append", default=None, metavar="IP",
                   help="Guvenilir IP (tespitten once elenir). Birden cok kez verilebilir.")
    p.add_argument("--quiet", action="store_true",
                   help="Sadece alarmlari goster; ozet ve IP tablosunu atla.")
    p.add_argument("--no-color", action="store_true",
                   help="ANSI renklerini kapat (renkli terminalde bile).")
    p.add_argument("--version", action="version", version=f"mini-siem {__version__}")
    return p


def run(argv: Optional[List[str]] = None, out=sys.stdout) -> int:
    """
    CLI'nin gercek is akisi. main() bunu cagirir; testler de dogrudan cagirabilir.

    Donus kodu (exit code):
        0 -> alarm yok / temiz
        1 -> en az bir alarm uretildi (CI/script'lerde 'bulgu var' sinyali)
        2 -> kullanim/dosya hatasi
    """
    args = build_parser().parse_args(argv)
    color = (not args.no_color) and _supports_color(out)

    # --- 1) Parse: dosyayi oku, Event listesine cevir ---
    try:
        events, unparsed = parse_file(args.logfile)
    except FileNotFoundError:
        print(f"HATA: dosya bulunamadi: {args.logfile}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"HATA: dosya okunamadi: {exc}", file=sys.stderr)
        return 2

    # --- 2) Depola: Event'leri ve unparsed sayisini EventStore'a koy ---
    store = EventStore()
    store.add_events(events)
    store.unparsed_count = len(unparsed)

    # --- 3) Tespit: tum kurallari calistir (engine siralamayi yapar) ---
    try:
        alerts = run_detections(
            events,
            window=args.window,
            threshold=args.threshold,
            enum_threshold=args.enum_threshold,
            allowlist=args.allow,
            min_fails=args.min_fails,
            success_window=args.success_window,
            anomaly_k=args.anomaly_k,
            anomaly_min_volume=args.anomaly_min_volume,
        )
    except ValueError as exc:
        # Kurallar anlamsiz esikleri (negatif pencere, threshold<1) reddeder.
        # Bunu traceback olarak degil, kullanim hatasi olarak bildiririz.
        print(f"HATA: gecersiz tespit ayari: {exc}", file=sys.stderr)
        return 2
    for a in alerts:
        store.add_alert(a)

    # --- 4) Sun: terminale yazdir ---
    if not args.quiet:
        _print_summary(store, color, out)
        _print_top_ips(store, out)
    _print_alerts(alerts, color, out)

    # --- 5) Istege bagli: JSON rapor dosyasi ---
    if args.json:
        try:
            store.to_json(args.json)
            print(f"\nJSON rapor yazildi: {args.json}", file=out)
        except OSError as exc:
            print(f"HATA: JSON yazilamadi: {exc}", file=sys.stderr)
            return 2

    # Alarm varsa exit 1 (script'ler 'bulgu var' diye anlasin), yoksa 0.
    return 1 if alerts else 0


def main() -> None:
    """Konsol giris noktasi: run()'in donus kodunu surece exit code olarak verir."""
    sys.exit(run())


if __name__ == "__main__":
    main()
