#!/usr/bin/env sh
set -eu

REPO="Hephaestus-Zero/hshield"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="${PREFIX}/bin"

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_from_source() {
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT
    echo "Building hshield from source..."
    if need_cmd git; then
        git clone --depth 1 "https://github.com/${REPO}.git" "${tmpdir}/hshield" >/dev/null
    elif need_cmd curl; then
        curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" | tar -xz -C "${tmpdir}"
        mv "${tmpdir}/hshield-main" "${tmpdir}/hshield"
    else
        echo "Error: need git or curl to fetch source" >&2
        exit 1
    fi
    make -C "${tmpdir}/hshield" CFLAGS="-std=c11 -O3 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror"
    mkdir -p "${BINDIR}"
    install -m 0755 "${tmpdir}/hshield/hshield" "${BINDIR}/hshield"
    install -m 0755 "${tmpdir}/hshield/hshield-supply-scan" "${BINDIR}/hshield-supply-scan"
}

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "${OS}" != "Linux" ]; then
    echo "Error: hshield requires Linux (Landlock LSM / fanotify / CN_PROC)" >&2
    exit 1
fi

if [ "${HSHIELD_FROM_SOURCE:-0}" != "1" ] && [ "${ARCH}" = "x86_64" ] && need_cmd curl; then
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
    TARBALL="hshield-linux-x86_64.tar.gz"
    if curl -fsSL "${BASE_URL}/${TARBALL}" -o "${tmpdir}/${TARBALL}" 2>/dev/null && \
       curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${tmpdir}/SHA256SUMS" 2>/dev/null; then
        (cd "${tmpdir}" && grep "${TARBALL}" SHA256SUMS | sha256sum -c - >/dev/null)
        tar -xzf "${tmpdir}/${TARBALL}" -C "${tmpdir}"
        mkdir -p "${BINDIR}"
        install -m 0755 "${tmpdir}/hshield" "${BINDIR}/hshield"
        install -m 0755 "${tmpdir}/hshield-supply-scan" "${BINDIR}/hshield-supply-scan"
        echo "Installed hshield and hshield-supply-scan to ${BINDIR} (verified SHA-256)"
        exit 0
    fi
fi

install_from_source
echo "Installed hshield and hshield-supply-scan to ${BINDIR}"
