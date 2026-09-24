#!/usr/bin/env bash
# Cross-compile d-hyperswarm's D to a static lib for Android arm64, matching the
# photo-wagon app's toolchain (LDC 1.42, ldc2-android.conf, -mtriple aarch64).
# ONLY d-hyperswarm's own modules go in the .a; deps (eventcore/vibe-core/…/libsodiumd)
# are -I only and compiled by the app at link, so no duplicate-module skew.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
LDC="$HOME/lab/android-d/ldc2-1.42.0-linux-x86_64/bin/ldc2"
CONF="$HOME/lab/photo-wagon/mobile/toolchain/ldc2-android.conf"
DUBP="$HOME/.dub/packages"
# ARCH=arm64 (default) or x86_64 (Waydroid): picks the LDC target triple.
ARCH="${ARCH:-arm64}"
case "$ARCH" in
  arm64) MTRIPLE=aarch64-linux-android ;;
  x86_64) MTRIPLE=x86_64-linux-android ;;
  *) echo "unknown ARCH=$ARCH (arm64|x86_64)" >&2; exit 2 ;;
esac
OUT="${1:-$ROOT/bin/android-$ARCH}"; mkdir -p "$OUT"
DEPI=(
  -I"$ROOT/source"
  -I"$DUBP/eventcore-0.9.39/eventcore/source"
  -I"$DUBP/vibe-core-2.14.0/vibe-core/source"
  -I"$DUBP/vibe-container-1.7.1/vibe-container/source"
  -I"$DUBP/taggedalgebraic-1.0.1/taggedalgebraic/source"
  -I"$DUBP/stdx-allocator-2.77.5/stdx-allocator/source"
  -I"$DUBP/libsodiumd-0.2.0_1.0.18/libsodiumd/source"
)
mapfile -t SRCS < <(find "$ROOT/source" -name '*.d')
"$LDC" -conf="$CONF" -mtriple="$MTRIPLE" -relocation-model=pic -O -lowmem -lib \
  -d-version=EventcoreEpollDriver \
  "${DEPI[@]}" "${SRCS[@]}" \
  -of="$OUT/libhsdswarm-android.a"
echo "build-dswarm-android: $OUT/libhsdswarm-android.a"
