"""
sliding_window.py — Kurallarin ortak "en yogun kayan pencere" secicisi (dahili yardimci).

Bagimlilik: parser/events.py.

brute_force, sudo_brute_force ve su_brute_force ayni iki isaretcili (two-pointer)
algoritmayi kullanir. Bu modul yalnizca PENCERE SECIMINI yapar; olay turu, gruplama,
esik, severity, Alert, aciklama, kanit siniri ve allowlist tamamen kurallarda kalir.

SLIDING WINDOW NASIL CALISIR:
  - Olaylari zamana gore sirala.
  - 'left' ve 'right' iki isaretci. right'i ileri kaydirirken, pencere genisligi
    (ts[right] - ts[left]) 'window'u ASARSA left'i ileri it. Yani fark tam 'window'
    saniye ise olay pencerede kalir: sinir KAPSAYICIDIR.
  - Boylece her an [left..right] araligi en fazla 'window' saniyelik bir penceredir.
  - Gorulen EN BUYUK pencereyi tutariz. Guncelleme yalnizca '>' ile yapilir; esit
    buyuklukte baska bir pencere bulunursa ILK (en erken) maksimum korunur.
Bu yontem O(n log n) siralama + O(n) taramadir.
"""

from parser.events import Event


def densest_window(events: list[Event], window: int) -> list[Event]:
    """
    En yogun kapsayici 'window' saniyelik olay penceresini kronolojik liste olarak dondurur.

    Parametreler:
      events : tek bir gruba ait olaylar (sirasi onemsiz; liste degistirilmez).
      window : pencere genisligi (saniye). On kosul: window >= 0 — dogrulama ve hata
               mesajlari cagiran kuralin sorumlulugudur.

    Donus: en yogun penceredeki olaylar, zamana gore sirali. Bos girdi -> [].
      - Esit yogunlukta birden cok pencere varsa ILK (en erken) pencere doner.
      - Ayni zaman damgali olaylar girdi sirasini korur (kararli siralama).
    """
    if not events:
        return []

    # sorted(): cagiranin listesini degistirmez; kararli oldugu icin ayni zamanli
    # olaylar girdi sirasini korur (kurallarin eski list.sort() davranisiyla ayni).
    ordered = sorted(events, key=lambda ev: ev.timestamp)
    times = [ev.timestamp.timestamp() for ev in ordered]  # epoch saniye

    left = 0
    best_count = 0
    best_left = best_right = 0  # en yogun pencerenin sinirlari

    for right in range(len(times)):
        # Pencere 'window'u astiysa sol kenari ileri it ('>' -> fark == window icerde).
        # 'left < right' korumasi: pencere tek olayin altina INEMEZ.
        while left < right and times[right] - times[left] > window:
            left += 1
        current = right - left + 1
        if current > best_count:  # '>' : esitlikte ilk maksimum korunur
            best_count = current
            best_left, best_right = left, right

    return ordered[best_left : best_right + 1]
