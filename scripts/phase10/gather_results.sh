#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PKG_DIR="$ROOT/phase10/package"
mkdir -p "$PKG_DIR"

echo "Copying figures previews..."
mkdir -p "$PKG_DIR/figures"
cp -r "$ROOT/figures"/* "$PKG_DIR/figures/" 2>/dev/null || true

echo "Copying results and manifests..."
mkdir -p "$PKG_DIR/results" "$PKG_DIR/phase5" "$PKG_DIR/phase8" "$PKG_DIR/phase9"
cp -r "$ROOT/results"/* "$PKG_DIR/results/" 2>/dev/null || true
cp -r "$ROOT/phase5"/* "$PKG_DIR/phase5/" 2>/dev/null || true
cp -r "$ROOT/phase8"/* "$PKG_DIR/phase8/" 2>/dev/null || true
cp -r "$ROOT/phase9"/* "$PKG_DIR/phase9/" 2>/dev/null || true

echo "Copying scripts and plots used to regenerate figures..."
mkdir -p "$PKG_DIR/scripts" "$PKG_DIR/plots"
cp -r "$ROOT/scripts/plotting" "$PKG_DIR/scripts/" 2>/dev/null || true
cp -r "$ROOT/scripts/phase10" "$PKG_DIR/scripts/" 2>/dev/null || true
cp -r "$ROOT/plots"/* "$PKG_DIR/plots/" 2>/dev/null || true

echo "Note: phase7/secure is not copied by default to avoid publishing sensitive transcripts. If reviewer access is authorized, copy them manually to phase10/package/phase7_secure/ and document access controls."

echo "Creating tar archive phase10/package.tar.gz"
cd "$ROOT/phase10"
tar -czf package.tar.gz package
echo "Created package.tar.gz in phase10/"
