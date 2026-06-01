# Mini SIEM

Linux `auth.log` dosyalarını analiz eden küçük bir **SIEM** (Security Information and Event Management) aracı. Ham log satırlarını yapılandırılmış olaylara çevirir, üzerinde güvenlik tespit kuralları çalıştırır ve sonucu hem terminalde hem de web panosunda gösterir.

> Çekirdek (parser / detection / storage / cli) **saf stdlib** ile çalışır — tek harici bağımlılık web panosu için `flask`.

---

## Özellikler

- **Parser** — `sshd` / `sudo` / PAM satırlarını regex ile `Event` nesnelerine çevirir. Eşleşmeyen satırları sessizce yutmaz, sayar ve raporlar.
- **Tespit kuralları:**
  | Kural | Ne yakalar | Önem |
  |-------|-----------|------|
  | `brute_force` | Bir IP'den kısa pencerede çok sayıda başarısız parola | düşük |
  | `user_enumeration` | Bir IP'nin çok sayıda **farklı** kullanıcı adı denemesi | orta |
  | `fail_then_success` | Ardışık başarısızlıkların ardından **başarılı** giriş (olası başarılı brute-force) | yüksek |
  | `anomaly` | Hacim olarak istatistiksel aykırı (z-score) IP'ler | değişken |
- **Allowlist** — güvenilir IP'ler tespitten **önce** elenir (yanlış alarm üretmesin).
- **İki arayüz, tek mantık** — CLI ve pano aynı `parse → store → run_detections` akışını kullanır; kurallar tek yerde (`detection/engine.py`).
- **JSON çıktı** — `--json` ile özet + olaylar + alarmlar dışa aktarılır.

---

## Kurulum

```bash
pip install -r requirements.txt   # sadece flask (pano için)
```

Python 3.11+ gerekir (`StrEnum` kullanılıyor). Geliştirme 3.13 üzerinde doğrulandı.

---

## Kullanım

### CLI

```bash
python cli.py sample_auth.log                          # terminal raporu
python cli.py sample_auth.log --json rapor.json        # JSON dışa aktar
python cli.py sample_auth.log --window 300 --threshold 5
python cli.py sample_auth.log --allow 198.51.100.5     # güvenilir IP
python cli.py sample_auth.log --quiet                  # sadece alarmlar
```

**Çıkış kodu:** alarm varsa `1`, temizse `0`, kullanım/dosya hatasında `2` (script'lerde "bulgu var mı" sinyali olarak kullanılabilir).

### Web panosu

```bash
python -m dashboard.app sample_auth.log                # http://127.0.0.1:5000
python -m dashboard.app sample_auth.log --host 0.0.0.0 --port 8080
```

Pano rotaları: `/` (HTML), `/api/summary`, `/api/alerts`, `/api/timeline` (JSON).

> Güvenlik: `--debug` **varsayılan kapalı**, host **varsayılan `127.0.0.1`**. Dışa açmak bilinçli bir seçimdir (`--host 0.0.0.0`).

---

## Proje yapısı

```
MiniSiem/
├── parser/
│   ├── events.py          # Event, EventType veri modeli (graf seviyesi 0)
│   └── auth_parser.py     # auth.log -> Event (iki aşamalı regex parse)
├── detection/
│   ├── alert.py           # Alert, Severity veri modeli
│   ├── brute_force.py     # kayan pencere brute-force tespiti
│   ├── enumeration.py     # kullanıcı enumeration tespiti
│   ├── fail_then_success.py
│   ├── anomaly.py         # z-score hacim anomalisi
│   └── engine.py          # tüm kuralları çalıştırıp sıralar
├── storage/
│   └── store.py           # EventStore (bellek + JSON, SQLite'a geçişe hazır)
├── dashboard/
│   ├── app.py             # Flask uygulaması (application factory)
│   └── templates/index.html
├── cli.py                 # komut satırı arayüzü
├── sample_auth.log        # örnek log (RFC5737 test IP'leri)
└── requirements.txt
```

Bağımlılık akışı (en az bağımlıdan en çoğa): `events`/`alert` → `auth_parser`/`store`/kurallar → `engine` → `cli`/`dashboard`.

---

## Örnek çıktı

`sample_auth.log` üzerinde: **36 olay, 31 başarısız giriş, 6 benzersiz IP, 5 alarm.**

```
[ HIGH ] fail_then_success  192.0.2.30 — 6 başarısız denemenin ardından BAŞARILI giriş (deploy)
[MEDIUM] user_enumeration    192.0.2.20 — 7 farklı kullanıcı adı denendi
[ LOW  ] brute_force         192.0.2.10 — 56 saniyede 8 başarısız parola denemesi
```

Her alarm; ilgili IP, olay sayısı, zaman penceresi ve **ham log satırlarından kanıt** içerir.

---

## Tasarım notları

- **Storage soyutlaması:** CLI/pano doğrudan listeye değil `EventStore` metodlarına konuşur. JSON katmanı ileride `INSERT INTO ...` ile SQLite'a çevrilse dışarıdaki kod değişmez.
- **Yıl çıkarımı:** `auth.log` yıl bilgisi içermez; parser referans yılı ekler ve yılbaşı geçişinde tarihin geleceğe kaymasını engeller.
- **Genişletme:** Yeni bir kural eklemek = `detection/` altına bir fonksiyon + `engine.py`'ye bir satır. CLI ve pano değişmez.

---

## Geliştirme

Bu proje, bir Claude Code + Ollama ajan pipeline'ı ile dosya dosya inşa edildi. Süreç kayıtları:
`logs/`, `context_store.json`, `dependency_graph.json`, `pipeline_raporu.json`.
