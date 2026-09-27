#!/usr/bin/env bash
set -euo pipefail

REPO="ternbusty/nacre"
INSTALL_DIR="/usr/local/lib/nacre"
BIN_LINK="/usr/local/bin/nacre"

VERSION="${NACRE_VERSION:-}"
if [ "${1:-}" = "--version" ] && [ -n "${2:-}" ]; then
  VERSION="$2"
  shift 2
fi

VERSION="${VERSION#v}"

if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -oE '"tag_name":\s*"v[^"]+"' | sed -E 's/.*"v([^"]+)".*/\1/')"
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

curl -fsSL "https://github.com/$REPO/archive/refs/tags/v${VERSION}.tar.gz" | tar xz -C "$TMP"

rm -rf "$INSTALL_DIR"
mv "$TMP/nacre-${VERSION}" "$INSTALL_DIR"
ln -sf "$INSTALL_DIR/nacre" "$BIN_LINK"

echo "Installed nacre ${VERSION}"
echo "  $INSTALL_DIR"
echo "  $BIN_LINK -> $INSTALL_DIR/nacre"
