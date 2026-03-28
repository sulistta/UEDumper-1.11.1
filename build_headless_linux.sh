#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$ROOT/build"
OUT_BIN="$OUT_DIR/uedumper-headless"

mkdir -p "$OUT_DIR"

c++ \
  -std=c++20 \
  -O2 \
  -pthread \
  -DUEDUMPER_HEADLESS \
  -I"$ROOT/UEDumper" \
  -I"$ROOT/UEDumper/Resources/Json" \
  -I"$ROOT/UEDumper/Resources/AES" \
  "$ROOT/UEDumper/headless_main.cpp" \
  "$ROOT/UEDumper/Memory/Memory.cpp" \
  "$ROOT/UEDumper/Frontend/Windows/LogWindow.cpp" \
  "$ROOT/UEDumper/Settings/EngineSettings.cpp" \
  "$ROOT/UEDumper/Engine/Core/Core.cpp" \
  "$ROOT/UEDumper/Engine/Core/ObjectsManager.cpp" \
  "$ROOT/UEDumper/Engine/UEClasses/UnrealClasses.cpp" \
  "$ROOT/UEDumper/Engine/Generation/SDK.cpp" \
  "$ROOT/UEDumper/Engine/Generation/MDK.cpp" \
  "$ROOT/UEDumper/Resources/AES/AES.cpp" \
  -o "$OUT_BIN"

printf 'Built %s\n' "$OUT_BIN"
