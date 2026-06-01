"""
fail_then_success.py — "Cok basarisiz, sonra basarili" kalibi (YUKSEK oncelik).

Bagimlilik: parser/events.py, detection/alert.py.

FIKIR: En tehlikeli senaryo: bir IP defalarca basarisiz olur, SONRA bir
"Accepted" gelir. Bu, brute-force'un MUHTEMELEN BASARDIGI anlamina gelir —
yani saldirgan dogru parolayi bulmus olabilir. Bu yuzden severity = HIGH.

ALGORITMA (IP basina, zaman sirali):
  - Olaylari IP'ye gore grupla, zamana gore sirala.
  - Sirayla gez; ardisik basarisizliklari say.
  - Bir ACCEPTED_LOGIN gorunce: oncesinde >= min_fails basarisizlik varsa
    ve bu basarili giris penceredeyse -> alarm. Sayaci sifirla.
"""

from parser.events import Event, EventType
from detection.alert import Alert, Severity


def detect_fail_then_success(
    events: list[Event],
    min_fails: int = 3,
    window: int = 600,
) -> list[Alert]:
    """
    "Basarisiz sonra basarili" alarmlari uretir.

    Parametreler:
      min_fails : basariliyi suheli yapan, oncesindeki min. ardisik basarisizlik (varsayilan 3).
      window    : son basarisizlik ile basari arasindaki max. sure (saniye, varsayilan 600=10dk).
                  Cok zaman gectiyse muhtemelen mesru kullanicidir, alarm uretme.

    Donus: her tetikleyen (IP, basari ani) icin bir Alert.
    """
    alerts: list[Alert] = []

    by_ip: dict[str, list[Event]] = {}
    for e in events:
        # Bu kuralı sadece parola/giris olaylari ilgilendirir.
        if e.source_ip and e.event_type in (
            EventType.FAILED_PASSWORD,
            EventType.INVALID_USER,
            EventType.ACCEPTED_LOGIN,
        ):
            by_ip.setdefault(e.source_ip, []).append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda ev: ev.timestamp)

        fail_streak: list[Event] = []  # ardisik basarisizliklar (kanit icin tutariz)
        for e in ip_events:
            if e.is_failure:
                fail_streak.append(e)
            elif e.is_success:
                # Basari geldi: oncesinde yeterli basarisizlik var mi?
                if len(fail_streak) >= min_fails:
                    gap = e.timestamp.timestamp() - fail_streak[-1].timestamp.timestamp()
                    if gap <= window:
                        start = fail_streak[0].timestamp.strftime("%H:%M:%S")
                        end = e.timestamp.strftime("%H:%M:%S")
                        alerts.append(
                            Alert(
                                rule_name="fail_then_success",
                                severity=Severity.HIGH,  # olasi BASARILI brute-force
                                source_ip=ip,
                                count=len(fail_streak),
                                time_window=f"{start}-{end}",
                                description=(
                                    f"{ip}: {len(fail_streak)} basarisiz denemenin ardindan "
                                    f"BASARILI giris (kullanici: {e.username}). "
                                    f"Olasi basarili brute-force - ACIL incele."
                                ),
                                # Kanit: basarisizliklar + basari satiri.
                                evidence=[ev.raw_line for ev in fail_streak[-5:]] + [e.raw_line],
                            )
                        )
                fail_streak = []  # basari sonrasi sayaci sifirla (yeni dizi baslasin)

    return alerts
