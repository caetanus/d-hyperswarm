#!/usr/bin/env bash
# Builds the vendored libudx as ONE C++ translation unit enclosed in `namespace udx`
# (see vendor/libudx-amalgam/udx_amalgam.cpp) into bin/libhsudx.a. Run by dub as a
# preBuildCommand.
#
# Compiled as C++ (g++) so every libudx symbol is mangled under udx:: and nothing
# leaks as a global C symbol. -fpermissive downgrades C's implicit void*->T*
# conversions (libudx is C) to warnings. The uv facade the archive references stays
# extern "C" as hsuv_* (resolved by the D facade); D calls the udx:: API via
# extern(C++, "udx").
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CXX="${CXX:-g++}"
mkdir -p "$ROOT/bin"

"$CXX" -x c++ -std=c++17 -fpermissive -O2 -fPIC \
    -I"$ROOT/vendor/libudx-shim" \
    -I"$ROOT/vendor/libudx/include" \
    -I"$ROOT/vendor/libudx/src" \
    -c "$ROOT/vendor/libudx-amalgam/udx_amalgam.cpp" \
    -o "$ROOT/bin/udx_amalgam.o"

rm -f "$ROOT/bin/libhsudx.a"
ar rcs "$ROOT/bin/libhsudx.a" "$ROOT/bin/udx_amalgam.o"
echo "build-libudx: bin/libhsudx.a (amalgamated C++, namespace udx)"
