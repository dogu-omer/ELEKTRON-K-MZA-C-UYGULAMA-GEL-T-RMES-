# Güvenlik / Security

- PIN hiçbir zaman komut satırı argümanı olarak alınmaz, loglanmaz, diske yazılmaz; kullanım sonrası bellekte sıfırlanır.
- Özel anahtar kartta kalır; karta yalnızca özet (DigestInfo) gönderilir.
- XML okuyucularda DTD ve harici varlıklar kapalıdır (XXE koruması).
- CSV raporlarında Excel formül enjeksiyonuna karşı kaçış yapılır.
- `--pfx` yalnız test içindir; yazılım anahtarı güvenli elektronik imza aracı değildir.

Güvenlik açığı bildirmek için lütfen herkese açık issue yerine GitHub "Security → Report a vulnerability" (özel bildirim) kullanın.
Please report vulnerabilities privately via GitHub Security Advisories.
