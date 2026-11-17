#!/usr/bin/env bash
# Üretilen imzaları bağımsız araçlarla doğrular: OpenSSL (CAdES), Poppler pdfsig (PAdES), xmlsec1 (XAdES).
# Verifies produced signatures with independent tools.
set -euo pipefail
command -v pdfsig >/dev/null || sudo apt-get install -y poppler-utils xmlsec1 >/dev/null
W="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.pem" -days 2 \
  -subj "/CN=Interop Test/C=TR" -addext "keyUsage=critical,nonRepudiation,digitalSignature" 2>/dev/null
openssl pkcs12 -export -inkey "$W/k.pem" -in "$W/c.pem" -out "$W/t.p12" -passout pass:test
mkdir -p "$W/in"
echo "merhaba" > "$W/in/not.txt"
echo '<?xml version="1.0" encoding="UTF-8"?><evrak><konu>deneme</konu></evrak>' > "$W/in/veri.xml"
# Basit, geçerli PDF
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n164\n%%%%EOF\n' > "$W/in/belge.pdf"

echo test | dotnet run --project src/TopluImza.Cli -c Release -- sign "$W/in" --pfx "$W/t.p12" --pin-stdin --yes
openssl cms -verify -binary -inform DER -in "$W/in/not.txt.p7s" -content "$W/in/not.txt" -CAfile "$W/c.pem" -purpose any -out /dev/null
pdfsig "$W/in/belge_imzali.pdf" | tee "$W/pdfsig.txt"
grep -q "Signature is Valid" "$W/pdfsig.txt"
grep -q "ETSI.CAdES.detached" "$W/pdfsig.txt"
xmlsec1 --verify --trusted-pem "$W/c.pem" --id-attr:Id SignedProperties "$W/in/veri_imzali.xml"
echo "Çapraz doğrulama başarılı / interop OK"
rm -rf "$W"
