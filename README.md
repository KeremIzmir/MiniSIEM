# Mini SIEM

[![CI](https://github.com/KeremIzmir/MiniSIEM/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KeremIzmir/MiniSIEM/actions/workflows/ci.yml)

Linux `auth.log` dosyalarını analiz eden küçük bir **SIEM** (Security Information and Event Management) aracı. Ham log satırlarını yapılandırılmış olaylara çevirir, üzerinde güvenlik tespit kuralları çalıştırır ve sonucu hem terminalde hem de web panosunda gösterir.

> Çekirdek (parser / detection / storage / cli) **saf stdlib** ile çalışır — tek harici bağımlılık web panosu için `flask`.

---

## Özellikler

- **Parser** — `sshd` / `sudo` / PAM satırlarını regex ile `Event` nesnelerine çevirir. Eşleşmeyen satırları sessizce yutmaz, sayar ve raporlar. Geçersiz tarihli tek bir satır dosyanın geri kalanını iptal etmez.
- **Tespit kuralları:**

  | Kural | Ne yakalar | Önem |
  |-------|-----------|------|
  | `brute_force` | Bir IP'den kısa pencerede çok sayıda başarısız parola | eşiğin kaç katı aşıldığına göre `low` → `medium` → `high` |
  | `user_enumeration` | Bir IP'nin çok sayıda **farklı** kullanıcı adı denemesi | eşiğin 2 katından az `medium`, fazlası `high` |
  | `fail_then_success` | Ardışık başarısızlıkların ardından **başarılı** giriş (olası başarılı brute-force) | daima `high` |
  | `anomalous_ip` | Hacim olarak istatistiksel aykırı (z-score) IP'ler | başarısızlık oranı ≥ %80 ise `high`, değilse `medium` |
  | `sudo_brute_force` | Aynı host'ta aynı kullanıcının kısa pencerede tekrarlanan **başarısız sudo** kimlik doğrulamaları (olası yerel yetki yükseltme) | eşiğin 2 katından az `medium`, fazlası `high` |
  | `su_brute_force` | Aynı host'ta aynı **yerel aktörün** kısa pencerede tekrarlanan **başarısız `su`** denemeleri; aktörün farklı hedef hesaplara denemeleri tek grupta birleşir (olası yerel hesap geçişi veya parola tahmini) | eşiğin 2 katından az `medium`, fazlası `high` |
  | `su_fail_then_success` | Aynı host'ta aynı **aktörün aynı hedef hesaba** tekrarlanan başarısız `su` denemelerinin ardından util-linux `su`'nun kaydettiği **başarılı geçiş** | daima `high` |

  Önem derecesi sabit değildir; her kural bulgunun büyüklüğüne göre hesaplar.

- **Allowlist** — güvenilir IP'ler tespitten **önce** elenir (yanlış alarm üretmesin). Yalnızca kaynak IP'si olan olayları etkiler: tipik yerel sudo/su olaylarında IP bulunmadığından `sudo_brute_force` ve `su_brute_force` alarmlarını **bastırmaz**. Bir olayda kaynak IP gerçekten doluysa (PAM `rhost`) o olay da bu IP filtresine tabidir.
- **İki arayüz, tek mantık** — CLI ve pano aynı `parse → store → run_detections` akışını kullanır; kurallar tek yerde (`detection/engine.py`) ve **her iki arayüz de aynı ayar yüzeyini** sunar.
- **JSON çıktı** — `--json` ile özet + olaylar + alarmlar dışa aktarılır.
- **Log enjeksiyonuna karşı korumalı çıktı** — log satırları saldırgan kontrolündedir; terminale basılmadan önce ANSI/kontrol karakterleri etkisiz hale getirilir (bkz. *Güvenlik notları*).

---

## Kurulum

```bash
pip install -r requirements.txt   # sadece flask (pano için)
```

veya paket olarak (`mini-siem` ve `mini-siem-dashboard` komutlarını PATH'e ekler):

```bash
pip install .          # ya da geliştirme için: pip install -e .
```

Python 3.11+ gerekir (`StrEnum` kullanılıyor); CI 3.11 / 3.12 / 3.13 üzerinde koşar.

---

## Kullanım

### CLI

```bash
python cli.py sample_auth.log                          # terminal raporu
python cli.py sample_auth.log --json rapor.json        # JSON dışa aktar
python cli.py sample_auth.log --quiet                  # sadece alarmlar
python cli.py sample_auth.log --no-color               # ANSI renklerini kapat
python cli.py sample_auth.log --allow 192.0.2.10       # güvenilir IP (alarmı düşer)
python cli.py --version
```

Tespit eşikleri (hepsi isteğe bağlı):

| Bayrak | Varsayılan | Etkilediği kural |
|--------|-----------|------------------|
| `--window SANIYE` | 300 | `brute_force` kayan pencere genişliği |
| `--threshold N` | 5 | `brute_force` eşiği |
| `--enum-threshold N` | 5 | `user_enumeration` farklı kullanıcı eşiği |
| `--min-fails N` | 3 | `fail_then_success` min. başarısızlık |
| `--success-window SANIYE` | 600 | `fail_then_success` geriye bakma süresi |
| `--anomaly-k KAT` | 2.0 | `anomalous_ip` standart sapma katsayısı |
| `--anomaly-min-volume N` | 5 | `anomalous_ip` min. mutlak olay sayısı |
| `--sudo-window SANIYE` | 300 | `sudo_brute_force` kayan pencere genişliği |
| `--sudo-threshold N` | 3 | `sudo_brute_force` eşiği (aynı host + kullanıcı) |
| `--su-window SANIYE` | 300 | `su_brute_force` kayan pencere genişliği |
| `--su-threshold N` | 3 | `su_brute_force` eşiği (aynı host + aktör) |
| `--su-success-min-fails N` | 3 | `su_fail_then_success` başarıdan önceki min. başarısızlık (aynı host + aktör + hedef) |
| `--su-success-window SANIYE` | 600 | `su_fail_then_success` başarıdan geriye bakma süresi |

`sample_auth.log` yalnızca 2 başarısız sudo denemesi içerdiği için `sudo_brute_force` varsayılan ayarlarla tetiklenmez; kuralı görmek için `--sudo-threshold 2` kullanılabilir. Örnek logda `su` satırı yoktur; `su_brute_force` varsayılan örnek sonucunu değiştirmez.

**Çıkış kodu:** alarm varsa `1`, temizse `0`, kullanım/dosya/ayar hatasında `2` (script'lerde "bulgu var mı" sinyali olarak kullanılabilir).

### Web panosu

```bash
python -m dashboard.app sample_auth.log                # http://127.0.0.1:5000
python -m dashboard.app sample_auth.log --host 0.0.0.0 --port 8080
```

Pano, yukarıdaki tespit bayraklarının **hepsini** aynı isimler, varsayılanlar ve doğrulama kurallarıyla kabul eder (`--window`, `--threshold`, `--enum-threshold`, `--min-fails`, `--success-window`, `--anomaly-k`, `--anomaly-min-volume`, `--sudo-window`, `--sudo-threshold`, `--su-window`, `--su-threshold`, `--su-success-min-fails`, `--su-success-window`, `--allow`).

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
│   ├── anomaly.py         # leave-one-out z-score hacim anomalisi
│   ├── sudo_brute_force.py # host + kullanıcı bazlı başarısız sudo tespiti
│   ├── su_brute_force.py  # host + aktör bazlı başarısız su tespiti
│   ├── su_fail_then_success.py # aynı aktör+hedef için başarısız su ardından başarılı geçiş
│   ├── sliding_window.py  # ortak "en yoğun kayan pencere" seçicisi (dahili)
│   └── engine.py          # tüm kuralları çalıştırıp sıralar
├── storage/
│   └── store.py           # EventStore (bellek + JSON, SQLite'a geçişe hazır)
├── dashboard/
│   ├── app.py             # Flask uygulaması (application factory)
│   └── templates/index.html
├── tests/                 # parser, tespit, storage, engine, CLI ve pano testleri
├── .github/workflows/ci.yml
├── cli.py                 # komut satırı arayüzü
├── sample_auth.log        # örnek log (RFC5737 test IP'leri)
├── pyproject.toml         # paket metadata + pytest/coverage yapılandırması
├── requirements.txt       # çalıştırma bağımlılıkları (flask)
├── requirements-dev.txt   # test bağımlılıkları (pytest, pytest-cov)
└── LICENSE
```

Her paketin bir `__init__.py` dosyası vardır. Bağımlılık akışı (en az bağımlıdan en çoğa): `events`/`alert` → `auth_parser`/`store`/kurallar → `engine` → `cli`/`dashboard`.

---

## Örnek çıktı

`sample_auth.log` üzerinde: **36 olay, 31 başarısız giriş, 6 benzersiz IP, 6 alarm, 1 parse edilemeyen satır.**

```
=== ALARMLAR (6) ===
[ HIGH ] anomalous_ip
    IP        : 192.0.2.20
    Olay sayisi: 14
    Aciklama  : 192.0.2.20 anormal hacim: 14 olay (diger IP ortalamasi=3.8, esik=9.9).
                Basarisiz oran=100%, 7 farkli kullanici, private IP.

[ HIGH ] fail_then_success
    IP        : 192.0.2.30
    Olay sayisi: 6
    Zaman     : 05:52:00-05:52:36 (36s)
    Aciklama  : 192.0.2.30: 36 saniye icinde 6 basarisiz denemenin ardindan BASARILI
                giris (kullanici: deploy). Olasi basarili brute-force - ACIL incele.

[MEDIUM] user_enumeration
    IP        : 192.0.2.20
    Olay sayisi: 7
    Aciklama  : 192.0.2.20 adresi 7 FARKLI kullanici adi denedi
                (orn: admin, git, jenkins, oracle, postgres, test, ubuntu).

[ LOW  ] brute_force ×3
```

Her alarm olay sayısını içerir; ağ kaynaklı kurallarda ilgili IP de bulunur (`sudo_brute_force`, `su_brute_force` ve `su_fail_then_success` yerel olduğu için IP yerine açıklamada `kullanıcı@host` / `aktör@host` verir). Ek olarak:
- **Zaman penceresi** `brute_force`, `fail_then_success`, `sudo_brute_force`, `su_brute_force` ve `su_fail_then_success` alarmlarında bulunur (diğer iki kural zaman değil çeşitlilik/hacim tabanlıdır).
- **Ham log satırlarından kanıt** `anomalous_ip` dışındaki tüm kurallarda bulunur (o kural istatistik özeti üretir, tek bir satıra dayanmaz).

---

## Tasarım notları

- **Storage soyutlaması:** CLI/pano doğrudan listeye değil `EventStore` metodlarına konuşur. JSON katmanı ileride `INSERT INTO ...` ile SQLite'a çevrilse dışarıdaki kod değişmez.
- **Yıl çıkarımı:** `auth.log` yıl bilgisi içermez; parser referans yılı ekler ve yılbaşı geçişinde tarihin geleceğe kaymasını engeller. `Feb 29` gibi yalnızca artık yıllarda geçerli tarihler en yakın uygun yıla düşürülür; hiçbir yılda geçerli olmayan tarih (`Feb 31`) satırı *unparsed* sayılır — tek bozuk satır tüm dosyayı iptal etmez.
- **Anomali kuralı — maskeleme:** Eşik, adayın **kendisi hariç** diğer IP'lerden hesaplanır (*leave-one-out*). Aksi halde aykırı değer kendi eşiğini şişirir; anakütle sapmasıyla `n` örneklemde ulaşılabilecek en büyük z-score `sqrt(n-1)` olduğu için `k=2.0` ile 6'dan az IP'de alarm **matematiksel olarak imkânsız** olurdu.
- **`fail_then_success` penceresi:** Pencere, başarının son başarısızlığa uzaklığına değil **başarısızlıkların kendisine** uygulanır; böylece haftalar önceki denemeler sayıma girmez.
- **`sudo_brute_force`:** Yalnızca `SUDO_FAILURE` olaylarını (`pam_unix(sudo:auth): authentication failure` satırları) sayar ve `(host, kullanıcı)` bazında gruplar; farklı makineler ya da kullanıcılar birleşmez. Kayan pencere kapsayıcıdır (fark tam pencere kadarsa aynı penceredir), girdi sırasına bağlı değildir ve grup başına en yoğun pencereden tek alarm üretir. Kapsam: sudo'nun `N incorrect password attempts` özet satırı **desteklenmez** (bu kural tarafından sayılmaz). PAM `authentication failure` satırları süreç adına göre sınıflandırılır (sudo → `SUDO_FAILURE`, su → `SU_FAILURE`, sshd/login gibi diğerleri → `AUTH_FAILURE`); başka sudo log biçimleri bu özelliğin kapsamı dışındadır.
- **PAM alanları: aktör ve hedef:** PAM satırındaki `anahtar=değer` alanları tek tek ayrılır; `user=` araması asla `ruser=` içinden eşleşmez. `user=` **hedef** hesaptır; `ruser` / `logname` işlemi başlatan **aktördür**. `Event.actor_username` aktörü ayrı taşır (`ruser` → `logname` → yoksa boş); `user=` asla aktörün yerine kullanılmaz.
  - **su:** `username` = hedef hesap (`user=`), `actor_username` = `su`'yu çalıştıran aktör.
  - **sudo:** geriye uyumluluk için `username` değişmedi (parolayı yazan aktör: `ruser` → `logname` → `user`); aktör ayrıca `actor_username`'de de tutulur (aktör yoksa boş).
  - **sshd/login gibi diğer PAM olayları:** `username` = hedef hesap, `actor_username` boş.
  - `actor_username` JSON çıktısına eklenmiş yeni bir alandır (mevcut alanlar değişmedi).
- **`su_brute_force`:** Yalnızca `SU_FAILURE` olaylarını sayar ve `(host, aktör)` bazında gruplar: aynı aktörün farklı hedeflere denemeleri tek grupta birleşir, farklı aktörlerin aynı hedefe (örn. root) tekil hataları birleşmez. Aktörü bilinmeyen olay sayılmaz. Açıklama en yoğun penceredeki hedefleri sıralı ve en fazla 5 tane listeler. Kapsam: `su` sürecinin (syslog etiketi `su`) PAM `authentication failure` satırları; util-linux `su -l` / `su -` da dahildir (PAM servisi `su-l`, etiket yine `su`: `su[PID]: pam_unix(su-l:auth): …`). Ayrı bir `su-l` syslog etiketi, `runuser` ve eski `FAILED SU` satırları desteklenmez.
- **PAM tekrar özetleri:** `pam_unix`, aynı PAM işlemindeki ek başarısızlıkları `N more authentication failures` özet satırıyla yazabilir. Bu satırlar sayılan olay değildir (çift sayım olmasın diye). Bu yüzden `sudo_brute_force` ve `su_brute_force` tek tek parola istemlerini değil, parser'ın tanıdığı birincil başarısızlık olaylarını sayar.
- **`SU_SUCCESS` (başarılı su geçişi):** Tek kaynak util-linux `su`'nun kaydıdır: `su[PID]: (to <hedef>) <aktör> on <tty>`. `su` bu satırı PAM kimlik doğrulama, hesap kontrolü (gerekirse süresi dolmuş parola değişimi) ve hedef tutarlılık kontrolü **başarılı olduktan sonra**, kimlik bilgisi ve oturum kurulumundan **önce** yazar. Bu yüzden `SU_SUCCESS` "başarılı geçiş kaydedildi" demektir; parolanın girildiğini ya da kırıldığını (örn. root için `pam_rootok`) veya PAM oturumunun kesin açıldığını **kanıtlamaz**. `username` = hedef, `actor_username` = aktör (boşsa yok). Aktör, başarısız denemedeki PAM `ruser` ile aynı değerdir. PAM `session opened/closed` satırları (aktörü farklı mekanizmadan gelir, boş olabilir, `quiet` seçeneğiyle bastırılabilir) ve `FAILED SU` satırları bilinçli olarak **sayılmaz** (UNKNOWN); böylece tek bir `su` çağrısı iki kez sayılmaz. util-linux dışındaki `su` uygulamalarının başarı kayıtları desteklenmez.
- **`su_fail_then_success`:** Yalnızca `SU_FAILURE` ve `SU_SUCCESS` olaylarını kullanır ve **tam** `(host, aktör, hedef)` üçlüsüne göre gruplar; aktörü ya da hedefi bilinmeyen olay korelasyona girmez. Başarıdan geriye kapsayıcı pencere içindeki başarısızlıkları sayar (eski denemeler elenir), her başarıdan sonra diziyi sıfırlar ve alarmı daima `high` üretir. `count` yalnızca başarısızlıkları sayar; kanıt son 5 başarısızlık + başarı satırıdır. Aktörün farklı hedefleri taramasını `su_brute_force` yakalar; aynı dizi iki kuralı da tetikleyebilir (farklı anlamlar). Ağ kuralı `fail_then_success` değişmedi ve `SU_SUCCESS` olaylarını almaz. Kaynak IP'si (`rhost`) allowlist'te olan bir `SU_FAILURE` engine tarafından elenir ve korelasyon sayımını düşürebilir.
- **Genişletme:** Yeni bir kural eklemek = `detection/` altına bir fonksiyon + `engine.py`'ye bir satır. Kuralın ayarları dışarıya açılacaksa, iki arayüz aynı ayar yüzeyini koruyabilsin diye aynı bayraklar hem `cli.py`'ye hem `dashboard/app.py`'ye eklenir.

---

## Güvenlik notları

- **Terminal kaçış dizisi enjeksiyonu (CWE-117):** Bir SIEM'in işlediği log satırları saldırgan kontrolündedir — `Invalid user <ESC>[2J` gibi bir kullanıcı adıyla SSH'a bağlanmak yeterlidir. Ham satır kanıt olarak doğrudan basılırsa bu diziler analistin terminalinde çalışır. CLI, gösterimden hemen önce kontrol karakterlerini görünür `\xNN` biçimine çevirir. `--json` çıktısı ham veriyi korur (JSON kaçışları zaten güvenlidir).
- **Pano:** Jinja2 otomatik HTML-escape yapar; log satırındaki `<script>` etiket olarak değil metin olarak render edilir.
- **Geçersiz tespit ayarları** (negatif pencere, `threshold < 1`) traceback yerine çıkış kodu `2` ile reddedilir.

---

## Testler

```bash
pip install -r requirements-dev.txt   # pytest + pytest-cov
pytest                                # tüm testleri çalıştır
pytest --cov --cov-report=term-missing
```

`tests/` altında parser, yedi tespit kuralı, ortak pencere seçicisi, storage, engine, CLI ve web panosu için birim/uçtan-uca testleri vardır; güncel test sayısı ve kapsam için `pytest --cov` çıktısına bakın. Tespit kuralları gerçek saate ve örnek dosyaya bağlı kalmadan test edilebilsin diye `tests/conftest.py` doğrudan `Event` üreten bir fabrika (`make_event`) sunar.

`.github/workflows/ci.yml`, `main` hedefli pull request'lerde ve `main` branch'ine yapılan push/merge'lerde testleri Python 3.11–3.13 üzerinde, Linux'ta çalıştırır; örnek logda CLI'ın tam olarak `1` çıkış koduyla alarm verdiğini, paketin kurulabildiğini ve pano şablonunun **kurulu** pakete girdiğini doğrular.

---

## Lisans

MIT — bkz. [LICENSE](LICENSE).

---

## Geliştirme

Bu proje, bir Claude Code + Ollama ajan pipeline'ı ile dosya dosya inşa edildi. Süreç kayıtları bilinçli olarak depoda tutulur:
`logs/`, `context_store.json`, `dependency_graph.json`, `pipeline_raporu.json`.
