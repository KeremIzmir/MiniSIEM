"""
su_brute_force.py — Ayni host'ta ayni yerel AKTORUN kisa surede TEKRARLANAN basarisiz su denemeleri.

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: Tek bir basarisiz su siradan bir yazim hatasi olabilir. Ama ayni yerel hesap kisa
surede tekrar tekrar basarisiz oluyorsa bu daha degerli bir guvenlik sinyalidir: ele
gecirilmis bir oturumdan baska bir hesaba gecme (yerel yetki yukseltme) ya da parola
tahmin (credential guessing) denemesine isaret edebilir. Kural bunu kesin saldiri olarak
degil, incelenecek bir sinyal olarak raporlar.

NEDEN AKTOR ODAKLI: Anahtar (host, actor_username). Boylece ayni aktorun farkli hedeflere
(root, postgres, deploy ...) yaptigi denemeler TEK grupta birlesir — hedef degistiren
saldirgan parcalanmaz. Farkli aktorlerin ayni hedefe (orn. root) yaptigi tekil hatalar ise
birlesmez; bagimsiz kisilerin yazim hatalari tek alarma donusmesin diye.
  - actor_username : su'yu calistiran hesap (parser: PAM ruser > logname).
  - username       : gecilmek istenen HEDEF hesap (PAM user=).
Aktoru bilinmeyen olay sayilmaz; hedef ASLA aktor yerine kullanilmaz.

NE SAYILIR: Parser'in tanidigi birincil SU_FAILURE olaylari. pam_unix, ayni PAM islemindeki
ek hatalari "N more authentication failures" ozetiyle yazabilir; bu satirlar sayilmaz.
Yani kural tek tek parola istemlerini degil, taninan basarisizlik olaylarini sayar.

ALGORITMA: En yogun pencereyi ortak iki isaretcili (two-pointer) secici bulur
(detection/sliding_window.py; ayrintili aciklama orada). Pencere KAPSAYICIDIR: iki olay
arasindaki fark tam 'window' saniye ise ayni penceredeler. Esit yogunlukta ILK pencere
kazanir.

IP ALLOWLIST: Engine'in --allow filtresi source_ip'e bakar. Tipik yerel su olayinda IP
yoktur, bu yuzden bu olaylar allowlist'ten etkilenmez. Olayda gercekten bir kaynak IP
varsa (rhost dolu) mevcut engine on-filtresi gecerlidir.
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity
from detection.sliding_window import densest_window

# Aciklamada gosterilecek en fazla hedef sayisi. Kullanici adlari log'dan gelir
# (saldirgan kontrolunde olabilir); sinir, alarm metninin sinirsiz buyumesini onler.
_MAX_TARGETS = 5


def _format_targets(window_events: list[Event]) -> str:
    """En yogun penceredeki benzersiz hedefleri sirali, en fazla _MAX_TARGETS tane yazar."""
    targets = sorted({e.username for e in window_events if e.username})
    if not targets:
        return "bilinmiyor"  # savunma amacli: parser SU_FAILURE icin hedefi zorunlu tutar
    shown = ", ".join(targets[:_MAX_TARGETS])
    rest = len(targets) - _MAX_TARGETS
    return f"{shown} (+{rest} daha)" if rest > 0 else shown


def detect_su_brute_force(
    events: list[Event],
    window: int = 300,
    threshold: int = 3,
) -> list[Alert]:
    """
    Tekrarlanan basarisiz su kimlik dogrulamasi alarmlari uretir.

    Parametreler:
      window    : pencere genisligi (saniye). Varsayilan 300 = 5 dakika.
      threshold : pencerede alarm icin gereken min. basarisizlik. Varsayilan 3: MiniSIEM'in
                  sectigi proje varsayilanidir (tek bir yazim hatasi alarm uretmesin diye);
                  gerekirse --su-threshold ile ayarlanir.

    Donus: her tetikleyen (host, actor_username) icin EN FAZLA bir Alert (en yogun pencereden).

    Severity: threshold <= sayi < 2*threshold -> MEDIUM, sayi >= 2*threshold -> HIGH.
    LOW yok: esik zaten tekil yazim hatalarini eler. Hedef hesaba (orn. root) gore ozel
    onem uygulanmaz; hangi hesabin ayricalikli oldugu olay verisinden guvenle bilinemez.

    Hata: window negatif ya da threshold 1'den kucukse ValueError — olay olmasa bile
    (dogrulama filtrelemeden ONCE yapilir; gecersiz ayar sessizce kabul edilmesin).
    """
    if window < 0:
        raise ValueError(f"su window negatif olamaz: {window}")
    if threshold < 1:
        raise ValueError(f"su threshold en az 1 olmali: {threshold}")

    alerts: list[Alert] = []

    # 1) Yalnizca SU_FAILURE; aktoru bilinmeyen olay atlanir.
    groups: dict[tuple[str, str], list[Event]] = {}
    for e in events:
        if e.event_type == EventType.SU_FAILURE and e.actor_username:
            groups.setdefault((e.host, e.actor_username), []).append(e)

    # 2) Her grup icin en yogun kayan pencere (ortak secici girdi sirasina guvenmez).
    for (host, actor), group in groups.items():
        # En yogun kapsayici pencere (kronolojik); kanit, sayim ve hedefler bu pencereden gelir.
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
                    rule_name="su_brute_force",
                    severity=sev,
                    source_ip=None,  # yerel islem: kaynak IP yok
                    count=best_count,
                    time_window=f"{start}-{end} ({span}s)",
                    description=(
                        f"{actor}@{host}: {span} saniyede {best_count} basarisiz su "
                        f"kimlik dogrulamasi (hedefler: {_format_targets(window_events)}; "
                        f"esik={threshold}/{window}s). "
                        f"Olasi yerel hesap gecisi veya parola tahmin aktivitesi."
                    ),
                    # Kanit: en yogun penceredeki ham satirlar, kronolojik, en fazla 10.
                    evidence=[ev.raw_line for ev in window_events[:10]],
                )
            )

    return alerts
