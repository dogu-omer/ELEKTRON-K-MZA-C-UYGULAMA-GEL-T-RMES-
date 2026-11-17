#!/usr/bin/env bash
# Tek dosyalık yayımlanmış ikiliden .deb paketi üretir.
# Usage: build-deb.sh <publish-dir> <version> <amd64|arm64> <out-dir>
set -euo pipefail
PUB="$1"; VER="$2"; ARCH="$3"; OUT="$4"
ROOT="$(mktemp -d)"
install -Dm755 "$PUB/topluimza" "$ROOT/usr/bin/topluimza"
if [[ -f "$PUB/topluimza-gui" ]]; then
  install -Dm755 "$PUB/topluimza-gui" "$ROOT/usr/bin/topluimza-gui"
  install -Dm644 "$(dirname "$0")/topluimza-gui.desktop" "$ROOT/usr/share/applications/topluimza-gui.desktop"
fi
install -Dm644 "$(dirname "$0")/../../LICENSE" "$ROOT/usr/share/doc/topluimza/copyright"
mkdir -p "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<CTRL
Package: topluimza
Version: $VER
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Omer Dogu <noreply@users.noreply.github.com>
Depends: libc6, libstdc++6
Recommends: pcscd, opensc
Homepage: https://github.com/dogu-omer/ELEKTRON-K-MZA-C-UYGULAMA-GEL-T-RMES-
Description: Toplu elektronik imza (CAdES, PAdES, XAdES) - AKIS / PKCS#11
 Klasordeki tum dosyalari tek PIN girisiyle AKIS akilli kart veya PKCS#11
 token ile imzalar; RFC 3161 zaman damgasi ve dogrulama destekler.
 Batch e-signature tool for folders with PKCS#11 smart cards.
CTRL
mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$ROOT" "$OUT/topluimza_${VER}_${ARCH}.deb"
rm -rf "$ROOT"
