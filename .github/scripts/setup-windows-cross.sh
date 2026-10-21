#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 zstd

archive="$RUNNER_TEMP/openssl.pkg.tar.zst"
curl --fail --location --retry 3 \
  https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-openssl-3.6.5-1-any.pkg.tar.zst \
  --output "$archive"
echo "389d1af21e99223d9e2cd32d4c073131b276da85be7636bd8d23571f6938864f  $archive" | sha256sum --check
mkdir -p "$RUNNER_TEMP/windows-openssl"
tar --zstd -xf "$archive" -C "$RUNNER_TEMP/windows-openssl"
echo "X86_64_PC_WINDOWS_GNU_OPENSSL_DIR=$RUNNER_TEMP/windows-openssl/mingw64" >> "$GITHUB_ENV"
echo 'X86_64_PC_WINDOWS_GNU_OPENSSL_STATIC=1' >> "$GITHUB_ENV"
