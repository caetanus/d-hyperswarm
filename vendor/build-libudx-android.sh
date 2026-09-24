#!/usr/bin/env bash
# Android libudx = the same plain-C build as the host, for an NDK target:
#   ARCH=arm64 (default) | x86_64  → bin/android-<arch>/libhsudx-android.a
# Kept as an entry point for the app's build; the work is in build-libudx.sh.
set -euo pipefail
ARCH="${ARCH:-arm64}" exec bash "$(dirname "$0")/build-libudx.sh" "$@"
