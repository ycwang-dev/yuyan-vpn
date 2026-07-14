#!/bin/bash
set -euo pipefail

OPENFORTIVPN_VERSION="1.24.1"
OPENFORTIVPN_COMMIT="a40a2d588733d48534eb78cd17b90142e5ba039b"
OPENSSL_VERSION="3.6.2"
OPENSSL_ARCHIVE_SHA256="aaf51a1fe064384f811daeaeb4ec4dce7340ec8bd893027eee676af31e83a04f"
ARM_SIDECAR_SHA256="34b86b94cba093fbbfa829109ade986c072117f55d45d6d742695e7d0d89b019"
REPOSITORY_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_PATH=${1:-"$REPOSITORY_ROOT/src-tauri/binaries/openfortivpn-x86_64-apple-darwin"}
WORK_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/openfortivpn-intel.XXXXXX")
OPENFORTIVPN_SOURCE_DIRECTORY="$WORK_DIRECTORY/openfortivpn"
OPENSSL_SOURCE_DIRECTORY="$WORK_DIRECTORY/openssl-$OPENSSL_VERSION"
OPENSSL_INSTALL_DIRECTORY="$WORK_DIRECTORY/openssl-install"

# 清理本次构建使用的临时源码目录。
cleanup() {
  rm -rf "$WORK_DIRECTORY"
}
trap cleanup EXIT

# 成功时只输出阶段摘要；失败时完整回放日志，避免 GitHub Annotations 被依赖构建噪声淹没。
run_logged() {
  local stage_name=$1
  shift
  local log_path="$WORK_DIRECTORY/$stage_name.log"
  echo "==> $stage_name"
  if ! "$@" >"$log_path" 2>&1; then
    cat "$log_path" >&2
    return 1
  fi
}

# GitHub 偶发 TLS 中断时重试固定 tag，且每次都从干净目录开始。
clone_openfortivpn() {
  local log_path="$WORK_DIRECTORY/openfortivpn-clone.log"
  for attempt in 1 2 3; do
    rm -rf "$OPENFORTIVPN_SOURCE_DIRECTORY"
    if git clone --depth 1 --branch "v$OPENFORTIVPN_VERSION" \
      https://github.com/adrienverge/openfortivpn.git \
      "$OPENFORTIVPN_SOURCE_DIRECTORY" >"$log_path" 2>&1; then
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      echo "openfortivpn 源码下载失败，准备第 $((attempt + 1)) 次尝试" >&2
      sleep "$attempt"
    fi
  done
  cat "$log_path" >&2
  return 1
}

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "x86_64" ]]; then
  echo "Intel openfortivpn 只能在 x86_64 macOS runner 上构建" >&2
  exit 1
fi

ARM_SIDECAR="$REPOSITORY_ROOT/src-tauri/binaries/openfortivpn-aarch64-apple-darwin"
echo "$ARM_SIDECAR_SHA256  $ARM_SIDECAR" | shasum -a 256 -c -

if ! command -v autoconf >/dev/null || ! command -v automake >/dev/null || ! command -v pkg-config >/dev/null; then
  HOMEBREW_NO_AUTO_UPDATE=1 brew install autoconf automake pkg-config >"$WORK_DIRECTORY/homebrew-tools.log" 2>&1 || {
    cat "$WORK_DIRECTORY/homebrew-tools.log" >&2
    exit 1
  }
fi

OPENSSL_ARCHIVE="$WORK_DIRECTORY/openssl-$OPENSSL_VERSION.tar.gz"
curl -fsSL --retry 3 --retry-all-errors \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
  -o "$OPENSSL_ARCHIVE"
echo "$OPENSSL_ARCHIVE_SHA256  $OPENSSL_ARCHIVE" | shasum -a 256 -c -
tar -xzf "$OPENSSL_ARCHIVE" -C "$WORK_DIRECTORY"

export MACOSX_DEPLOYMENT_TARGET=12.0
cd "$OPENSSL_SOURCE_DIRECTORY"
run_logged openssl-configure ./Configure darwin64-x86_64-cc \
  no-shared \
  no-tests \
  --prefix="$OPENSSL_INSTALL_DIRECTORY" \
  --openssldir="$OPENSSL_INSTALL_DIRECTORY/ssl"
run_logged openssl-build make -s -j"$(sysctl -n hw.logicalcpu)" build_sw
run_logged openssl-install make -s install_sw

OPENSSL_LIBRARY_DIRECTORY=$(dirname "$(find "$OPENSSL_INSTALL_DIRECTORY" -name libssl.a -type f -print -quit)")
test -f "$OPENSSL_LIBRARY_DIRECTORY/libssl.a"
test -f "$OPENSSL_LIBRARY_DIRECTORY/libcrypto.a"
export OPENSSL_CFLAGS="-I$OPENSSL_INSTALL_DIRECTORY/include"
export OPENSSL_LIBS="$OPENSSL_LIBRARY_DIRECTORY/libssl.a $OPENSSL_LIBRARY_DIRECTORY/libcrypto.a"

clone_openfortivpn
test "$(git -C "$OPENFORTIVPN_SOURCE_DIRECTORY" rev-parse HEAD)" = "$OPENFORTIVPN_COMMIT"
git -C "$OPENFORTIVPN_SOURCE_DIRECTORY" apply --check "$REPOSITORY_ROOT/scripts/patches/openfortivpn-1.24.1-http-status.patch"
git -C "$OPENFORTIVPN_SOURCE_DIRECTORY" apply "$REPOSITORY_ROOT/scripts/patches/openfortivpn-1.24.1-http-status.patch"

cd "$OPENFORTIVPN_SOURCE_DIRECTORY"
run_logged openfortivpn-autogen ./autogen.sh
run_logged openfortivpn-configure ./configure \
  --prefix=/usr/local \
  --sysconfdir=/etc \
  --enable-legacy-pppd \
  --with-pppd=/usr/sbin/pppd
run_logged openfortivpn-build make -s -j"$(sysctl -n hw.logicalcpu)"

file openfortivpn | grep -q 'x86_64'
test "$(./openfortivpn --version)" = "$OPENFORTIVPN_VERSION"
grep -a -q 'stage: fortisslvpn_xml' openfortivpn
xcrun vtool -show-build openfortivpn | grep -q 'minos 12.0'
if otool -L openfortivpn | grep -Eq '/(usr/local|opt/homebrew|Cellar|openfortivpn-intel)/'; then
  echo "Intel openfortivpn 仍依赖 Homebrew 动态库，禁止进入安装包" >&2
  otool -L openfortivpn >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
cp openfortivpn "$OUTPUT_PATH"
chmod 755 "$OUTPUT_PATH"
shasum -a 256 "$OUTPUT_PATH"
echo "Intel openfortivpn $OPENFORTIVPN_VERSION 构建与 macOS 12 兼容性校验通过"
