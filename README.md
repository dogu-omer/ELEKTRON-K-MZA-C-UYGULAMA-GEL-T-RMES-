# Elektronik İmza

RSA sertifikası kullanarak dosyalar için ayrık SHA-256 imzası oluşturup doğrulayan .NET 8 komut satırı uygulaması.

## Kullanım

Özel anahtarı içeren `.pfx` sertifikanız ve imzalamak istediğiniz dosyayla uygulamayı çalıştırın:

```sh
dotnet run --project ElektronikImza -- sign belge.pdf belge.pdf.sig imzalayan.pfx
```

PFX dosyası parola korumalıysa uygulama parolayı etkileşimli olarak ister. İmza dosyası önceden varsa üzerine yazılmaz.

İmzayı doğrulamak için imzalama sertifikasının `.cer` dosyasını (açık anahtar) kullanın:

```sh
dotnet run --project ElektronikImza -- verify belge.pdf belge.pdf.sig imzalayan.cer
```

Doğrulama, dosyanın imzadan sonra değiştirilip değiştirilmediğini ve verilen sertifikanın imzayı üretip üretmediğini kontrol eder; sertifika zincirini, iptal durumunu veya kimliğin güvenilirliğini değerlendirmez.

## Sınırlamalar

Bu örnek uygulama RSA (en az 2048 bit) ve PKCS#1 v1.5 imza biçimini kullanır. İmza, CMS/PKCS#7 kapsayıcısı değildir ve güvenilir zaman damgası içermez. Bu nedenle tek başına nitelikli elektronik imza oluşturduğu veya mevzuata uygunluğu garanti ettiği anlamına gelmez. Üretim ortamı için sertifika sağlayıcınızın akıllı kart/HSM entegrasyonu, sertifika doğrulaması ve ilgili mevzuat gereksinimleri ayrıca uygulanmalıdır.
