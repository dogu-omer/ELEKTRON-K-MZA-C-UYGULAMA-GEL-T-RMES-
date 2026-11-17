# TopluImza — Toplu Elektronik İmza (.NET)

[Türkçe](#türkçe) · [English](#english)

Bir klasördeki **tüm dosyaları tek seferde** AKİS akıllı kart (PKCS#11) ile imzalayan, çok platformlu (Linux, Windows, macOS) C# / .NET 10 LTS aracı. Komut satırı (`topluimza`) ve basit masaüstü arayüzü (`topluimza-gui`) içerir. Lisans: **GPL-3.0-only**.

---

## Türkçe

### Yönetici özeti

| Konu | Durum |
|---|---|
| Toplu imza | Klasör (isteğe bağlı alt klasörlerle) tek PIN ile imzalanır |
| PIN | Toplu işlem başına **bir kez** sorulur; günlüğe yazılmaz, diske kaydedilmez, işlem sonunda bellekten silinir |
| Biçimler | CAdES (`.p7s` ayrık / `.imz` ekli) her dosya için · PAdES (PDF) · XAdES-BES (XML, yalnızca RSA) |
| Seviyeler | BES, T (RFC 3161 zaman damgası) — CAdES ve PAdES |
| Doğrulama | `verify` komutu: imza + sertifika zinciri + OCSP/CRL (çevrimdışı mod mevcut) |
| Rapor | Her dosya için CSV (Excel uyumlu, `;`) ve JSON rapor, SHA-256 özetleri ile |
| Paketler | `.deb` (amd64/arm64), Windows MSI, macOS `.pkg`, tar.gz/zip — GitHub Actions ile |
| Test | xUnit; SoftHSM ile gerçek PKCS#11 testi; OpenSSL / pdfsig / xmlsec1 ile karşılıklı doğrulama |

### Özellikler

| Özellik | Açıklama |
|---|---|
| Biçim seçimi | `auto`: PDF → PAdES, XML → XAdES, diğerleri → CAdES. `--format cades` hepsini CAdES yapar |
| Çıktı adları | `belge.docx.p7s`, `belge.docx.imz` (`--attached`), `rapor_imzali.pdf`, `veri_imzali.xml` |
| Çıktı klasörü | `-o` ile ayrı klasör; giriş klasör yapısı korunur |
| Filtre | `--include "*.pdf"`, `--exclude "taslak*"`; gizli dosyalar, imza dosyaları ve raporlar atlanır |
| Güvenli yazım | Önce geçici dosyaya yazılır, kendi kendine doğrulanır, sonra yerine taşınır; doğrulamayı geçemeyen çıktı silinir |
| Kuru çalıştırma | `--dry-run`: kart açmadan neyin imzalanacağını listeler |
| İptal | Ctrl+C mevcut dosyayı bitirip güvenle durur |
| Sertifika seçimi | İnkâr edilemezlik (nonRepudiation) anahtar kullanımı olan nitelikli sertifika öncelikli; `--cert` ile etiket |

### Kurulum

| Platform | Paket | Not |
|---|---|---|
| Debian/Ubuntu/Pardus | `sudo apt install ./topluimza_<sürüm>_amd64.deb` | `pcscd` ve `opensc` önerilir |
| Windows 10/11 | `TopluImza-<sürüm>-win-x64.msi` | `topluimza` PATH'e eklenir |
| macOS | `TopluImza-<sürüm>-osx-arm64.pkg` | `/usr/local/bin/topluimza` |
| Taşınabilir | `tar.gz` / `zip` | .NET kurulumu gerekmez (self-contained) |

Sürümler: GitHub **Releases** sayfası. Her sürümde `SHA256SUMS` ve derleme kökeni (build provenance) kanıtı bulunur.

### AKİS kart hazırlığı

1. Kart okuyucu sürücüsü ve `pcscd` (Linux) çalışıyor olmalı.
2. AKİS PKCS#11 kütüphanesi kurulu olmalı (TÜBİTAK BİLGEM AKİS sürücüsü).
3. Kütüphane otomatik aranır; bulunamazsa `--lib` veya `ESIGN_PKCS11_LIB` ile verin:

| OS | Varsayılan aranan yollar (örnek) |
|---|---|
| Linux | `/usr/lib/libakisp11.so`, `/usr/lib/x86_64-linux-gnu/libakisp11.so` |
| macOS | `/usr/local/lib/libakisp11.dylib`, `/Library/AKIS/libakisp11.dylib` |
| Windows | `C:\Windows\System32\akisp11.dll` |

```bash
topluimza list-certs                 # karttaki sertifikaları listeler (PIN sorar)
```

### Kullanım

```bash
# Klasördeki tüm dosyaları imzala (alt klasörlerle), raporla
topluimza imzala ~/Belgeler/Sozlesmeler -r

# Ayrı çıktı klasörü, sadece PDF, zaman damgalı (T seviyesi)
topluimza sign ./gelen -o ./imzali --include "*.pdf" --tsa http://tsa.ornek.gov.tr

# Önce ne imzalanacağını gör
topluimza sign ./gelen -r --dry-run

# Doğrula (ayrık .p7s için özgün dosyalar aynı klasörde ya da --originals ile)
topluimza verify ./imzali -r --originals ./gelen --trust ./kokler
```

| Seçenek | Anlamı |
|---|---|
| `-r` | Alt klasörleri de işle |
| `-o, --out` | Çıktı klasörü |
| `--format auto\|cades` | Biçim seçimi |
| `--attached` | CAdES ekli (`.imz`) |
| `--tsa <url>` | RFC 3161 zaman damgası (veya `ESIGN_TSA_URL`) |
| `--hash sha256\|sha384\|sha512` | Özet algoritması |
| `--reason`, `--location` | PDF imza nedeni / yeri |
| `--overwrite` | Var olan çıktının üzerine yaz |
| `--no-verify` | İmza sonrası öz-doğrulamayı kapat (önerilmez) |
| `--report <yol>` | Rapor adı (varsayılan `imza-raporu-<zaman>.csv/.json`) |
| `-y, --yes` | Onay sorusunu atla |
| `--lib`, `--slot`, `--cert` | PKCS#11 kütüphanesi, yuva, sertifika etiketi |
| `--pin-stdin` | PIN'i standart girdiden oku (otomasyon) |
| `--trust <klasör>` | Güvenilen kök sertifikalar (veya `ESIGN_TRUST_DIR`) |
| `--offline` | OCSP/CRL sorgusu yapma |

**PIN komut satırı argümanı olarak kabul edilmez** (`--pin` reddedilir); süreç listesinde ve kabuk geçmişinde görünmesin diye.

Çıkış kodları: `0` başarılı · `1` hata · `2` kullanım hatası · `3` belirsiz · `4` geçersiz · `5` kısmi başarısızlık.

Ortam değişkenleri: `ESIGN_PKCS11_LIB`, `ESIGN_TSA_URL`, `ESIGN_TSA_USER` / `ESIGN_TSA_PASSWORD` (Basic kimlik doğrulamalı TSA), `ESIGN_TRUST_DIR`.

### Rapor örneği (CSV)

| Dosya | Biçim | Durum | Çıktı | SHA-256 | Doğrulandı | Mesaj |
|---|---|---|---|---|---|---|
| a.pdf | PAdES | İmzalandı | a_imzali.pdf | 9f…c1 | Evet | |
| b.docx | CAdES | İmzalandı | b.docx.p7s | 2a…7e | Evet | |
| c.pdf | PAdES | Hata | | | | Zaten imzalı PDF desteklenmez |

Gerçek raporda ayrıca boyut, süre ve UTC zaman sütunları bulunur.

CSV, Excel'de doğrudan açılır (UTF-8 BOM, `;` ayraç); formül enjeksiyonuna karşı hücreler kaçışlanır.

### Masaüstü arayüz

`topluimza-gui`: klasör seç → seçenekleri işaretle → PIN gir → **İmzala**. İlerleme çubuğu ve dosya bazlı günlük gösterilir; **Doğrula** ve **Durdur** düğmeleri vardır.

### Hukuki çerçeve ve sınırlar

| Konu | Açıklama |
|---|---|
| Dayanak | 5070 sayılı Elektronik İmza Kanunu: nitelikli sertifika + güvenli imza oluşturma aracı (AKİS) ile oluşturulan güvenli elektronik imza, elle atılan imza ile aynı hukuki sonucu doğurur |
| Standartlar | ETSI EN 319 122 (CAdES), EN 319 142 (PAdES), EN 319 132 (XAdES), RFC 5652 (CMS), RFC 3161 (zaman damgası), RFC 5035 (ESSCertIDv2) |
| Sınır | Bu yazılım BTK veya TÜBİTAK tarafından **sertifikalandırılmamıştır**; resmî uygunluk iddiası yoktur. Kurum içi kullanımdan önce karşı tarafın (ör. e-Yazışma, UYAP) doğrulayıcısıyla test edin |
| Uzun süreli arşiv | LT/LTA seviyeleri bu sürümde yok; Java projesi (ELEKTRONIK_IMZALAMA_PROGRAMI_MULTI_OS-a) LT/LTA destekler |
| İmzager | İmzager ile karşılıklı test, gerçek AKİS kartıyla imzalı dosyalar gerektirir; henüz yapılmadı |

### Güvenlik ve KVKK

- PIN `char[]` arabellekte tutulur, kullanım sonrası sıfırlanır; günlük, rapor ve istisna mesajlarına yazılmaz.
- Raporlarda kişisel veri olarak yalnızca imzalayan sertifika adı (CN) ve dosya adları bulunur; raporlar yerel diskte kalır, ağa gönderilmez.
- Ağ erişimi yalnızca kullanıcı istediğinde: TSA, OCSP, CRL.
- `*.pfx`, `*.p12`, `.env` dosyaları `.gitignore` ile dışlanır; depoda gizli anahtar bulunmaz.
- Güvenlik açığı bildirimi: [SECURITY.md](SECURITY.md).

### Derleme ve test

```bash
dotnet --version            # 10.0.1xx
dotnet build -c Release
dotnet test -c Release
# Gerçek PKCS#11 testi (SoftHSM):
source <(scripts/softhsm-setup.sh)
dotnet test -c Release
scripts/interop-check.sh    # OpenSSL / pdfsig / xmlsec1 ile çapraz doğrulama
```

Kart PIN deneme hakkını tüketmemek için yanlış-PIN testi yalnızca `TOPLUIMZA_TEST_ALLOW_WRONG_PIN=1` ile çalışır.

### Mimari

| Modül | Görev | Bağımlılık |
|---|---|---|
| `TopluImza.Core` | `ISigningToken`, özetler, `Secret` (PIN) | — |
| `TopluImza.Pkcs11` | AKİS/PKCS#11 oturumu, sertifika seçimi | Core, Pkcs11Interop |
| `TopluImza.Cades` | CAdES-BES/T, RFC 3161 istemcisi | Core, BouncyCastle |
| `TopluImza.Pades` | PAdES (ETSI.CAdES.detached) | Cades, PDFsharp |
| `TopluImza.Xades` | XAdES-BES enveloped | Core, System.Security.Cryptography.Xml |
| `TopluImza.Validation` | CMS / PDF / XML doğrulama, zincir, OCSP/CRL | Core, BouncyCastle |
| `TopluImza.Batch` | Klasör tarama, toplu imza, rapor | Yukarıdakiler |
| `TopluImza.Cli` | `topluimza` komutu | Batch, Pkcs11 |
| `TopluImza.Gui` | Avalonia masaüstü arayüz | Batch, Pkcs11 |

İmza motorları `ISigningToken` arayüzüne bağlıdır; kart, PFX (yalnızca test) veya ileride HSM/uzaktan imza aynı arayüzle takılabilir.

### Bağımlılık lisansları

| Paket | Sürüm | Lisans | GPL-3.0 uyumu |
|---|---|---|---|
| Pkcs11Interop | 5.3.0 | Apache-2.0 | Uyumlu |
| BouncyCastle.Cryptography | 2.7.0 | MIT | Uyumlu |
| PDFsharp | **6.2.4** (sabit) | MIT | Uyumlu |
| System.Security.Cryptography.Xml / Pkcs | 10.0.x | MIT | Uyumlu |
| Avalonia | 12.x | MIT | Uyumlu |

> **PDFsharp notu:** 6.3.0 ve sonrası AGPL-3.0'a geçti ve çalışma anında lisans denetimi yapıyor. Bu yüzden MIT lisanslı 6.2.4'te sabitlendi; Dependabot `>= 6.3.0` güncellemelerini yok sayar.

---

## English

### Summary

TopluImza signs **every file in a folder in one run** with a Turkish AKİS smart card over PKCS#11. Cross-platform (Linux, Windows, macOS), C# on .NET 10 LTS, GPL-3.0-only. It is a .NET port of the signing features of the Java project `ELEKTRONIK_IMZALAMA_PROGRAMI_MULTI_OS-a`, plus batch signing.

| Topic | Status |
|---|---|
| Batch | One folder (optionally recursive), one PIN prompt |
| PIN | Asked **once per batch**; never logged or stored; wiped from memory afterwards |
| Formats | CAdES detached `.p7s` / attached `.imz` for any file · PAdES for PDF · XAdES-BES for XML (RSA keys) |
| Levels | BES and T (RFC 3161 timestamp) for CAdES and PAdES |
| Verify | `verify` command: signature, chain, OCSP/CRL, offline mode |
| Report | Per-file CSV (Excel-friendly) and JSON with SHA-256 digests |
| Packages | `.deb`, Windows MSI, macOS `.pkg`, tar.gz/zip, built by GitHub Actions |

### Quick start

```bash
topluimza list-certs
topluimza sign ./inbox -r -o ./signed --tsa http://tsa.example
topluimza verify ./signed -r --originals ./inbox --trust ./roots
```

Exit codes: `0` ok, `1` error, `2` usage, `3` indeterminate, `4` invalid, `5` partial failure. The PIN is never accepted as a command-line argument; use the masked prompt or `--pin-stdin`.

### Legal limits

Built against ETSI EN 319 122/142/132, RFC 5652, RFC 3161 and RFC 5035. Under Turkish Law No. 5070, a secure electronic signature made with a qualified certificate on a secure signature-creation device has the same legal effect as a handwritten one. This software is **not certified** by BTK or TÜBİTAK; test it against the relying party's validator before production use. LT/LTA long-term levels are not implemented in this version.

### Build

```bash
dotnet build -c Release && dotnet test -c Release
```

See the Turkish sections above for options, architecture and dependency licenses (PDFsharp is pinned to MIT-licensed 6.2.4; 6.3.0+ is AGPL-3.0).

### License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).
