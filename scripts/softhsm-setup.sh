#!/usr/bin/env bash
# SoftHSM2 ile test amaçlı sanal PKCS#11 kart hazırlar (CI ve yerel geliştirme).
# Creates a throw-away SoftHSM2 token with an RSA signing key + certificate.
# Kullanım / usage:  source scripts/softhsm-setup.sh   (veya CI'da GITHUB_ENV'e yazar)
set -euo pipefail

WORK="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/topluimza-softhsm"
LIB=""
for d in /usr/lib /usr/local/lib /opt/homebrew/lib; do
  [[ -d "$d" && -z "$LIB" ]] && LIB="$(find "$d" \( -name 'libsofthsm2.so' -o -name 'libsofthsm2.dylib' \) 2>/dev/null | head -1 || true)"
done
if [[ -z "$LIB" ]]; then
  echo "libsofthsm2 bulunamadı: sudo apt-get install softhsm2 opensc" >&2
  exit 1
fi
PIN="${TOPLUIMZA_TEST_PIN:-123456}"

rm -rf "$WORK" && mkdir -p "$WORK/tokens"
cat > "$WORK/softhsm2.conf" <<CONF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$WORK/softhsm2.conf"

softhsm2-util --init-token --free --label "TOPLUIMZA TEST" --so-pin 87654321 --pin "$PIN" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" -days 30 \
  -subj "/CN=SoftHSM Test Imzaci/C=TR" -addext "keyUsage=critical,nonRepudiation,digitalSignature" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/k.pem" -outform DER -out "$WORK/k.der"
openssl x509 -in "$WORK/c.pem" -outform DER -out "$WORK/c.der"
pkcs11-tool --module "$LIB" --login --pin "$PIN" --write-object "$WORK/k.der" --type privkey --id 01 --label imza >/dev/null
pkcs11-tool --module "$LIB" --login --pin "$PIN" --write-object "$WORK/c.der" --type cert --id 01 --label imza >/dev/null
rm -f "$WORK/k.pem" "$WORK/k.der"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
    echo "TOPLUIMZA_TEST_PKCS11_LIB=$LIB"
    echo "TOPLUIMZA_TEST_PKCS11_PIN=$PIN"
    echo "TOPLUIMZA_TEST_ALLOW_WRONG_PIN=1"
  } >> "$GITHUB_ENV"
else
  export TOPLUIMZA_TEST_PKCS11_LIB="$LIB" TOPLUIMZA_TEST_PKCS11_PIN="$PIN" TOPLUIMZA_TEST_ALLOW_WRONG_PIN=1
fi
echo "SoftHSM hazır: $LIB (token: TOPLUIMZA TEST)"
