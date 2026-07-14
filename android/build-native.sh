#!/bin/bash
# Build the Rust core for arm64 and drop it where Gradle packages it from.
# Kept out of Gradle on purpose: cargo owns the Rust build, `externalNativeBuild`
# would only add CMake to the picture without owning anything.
set -euo pipefail

cd "$(dirname "$0")/.."

. "$HOME/.cargo/env"
export PATH="$HOME/.local/bin:$PATH"
export PROTOC="$HOME/.local/bin/protoc"
export ANDROID_NDK_HOME="$HOME/android-sdk/ndk/28.2.13676358"

OUT=android/app/src/main/jniLibs
mkdir -p "$OUT"

cargo ndk -t arm64-v8a --platform 26 -o "$OUT" \
    build --profile release-android -p pactmesh-android

# cargo-ndk also copies out the cdylibs of transitive crates that happen to build
# one (boringtun, tun, rustls-platform-verifier). Nothing links against them —
# libpactmesh_android.so is statically complete — and they would just bloat the APK.
find "$OUT" -name '*.so' ! -name 'libpactmesh_android.so' -delete

file "$OUT"/arm64-v8a/libpactmesh_android.so
