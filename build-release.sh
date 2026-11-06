#!/bin/bash
# Build a libVES.js release from source: liboqs and OpenSSL at the commits
# build-inputs.json pins, both WebAssembly engines, then both bundles with
# their hashes (.sri) and SBOM. The release build runs this, and
# repro/reproduce.sh runs a release's own copy of it to check that release.
#
# Usage: ./build-release.sh [--work DIR] [--out DIR] [--jobs N]
#
#   --work DIR   where liboqs and OpenSSL are fetched and built; must be new or
#                empty (default: a new directory in $TMPDIR, removed afterwards)
#   --out DIR    where build.js writes the release files (default: this directory)
#   --jobs N     parallel compile jobs (default: the number of CPUs)
#
# Needs bash, git, make, cmake, perl, node, and emscripten (emcc, emcmake,
# emmake, emconfigure) at the version build-inputs.json names. The build steps
# are in WasmOQS/Makefile and WasmECDH/Makefile, which map the source paths to
# fixed names, so the engines come out the same wherever this runs.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
WORK=
OUT=$ROOT
JOBS=$(nproc 2>/dev/null || echo 1)

die() { echo "build-release: $*" >&2; exit 2; }
say() { echo "== $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --work)    WORK=${2:?}; shift 2 ;;
        --out)     OUT=${2:?}; shift 2 ;;
        --jobs)    JOBS=${2:?}; shift 2 ;;
        -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)         die "unknown argument $1" ;;
    esac
done

for tool in git make cmake perl node emcc emcmake emmake emconfigure; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

# input <component> <field>: a field of a component in build-inputs.json
input() {
    node -e '
        const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        const c = j.components.find((c) => c.name === process.argv[2]);
        const v = c && c[process.argv[3]];
        if (v == null) process.exit(3);
        console.log(v);
    ' "$ROOT/build-inputs.json" "$1" "$2" || die "build-inputs.json has no $2 for $1"
}

# A different emscripten gives different engines. (sed -n 1p rather than
# head: head closing the pipe early can fail the command under pipefail.)
EM_WANT=$(input emscripten version)
EM_LINE=$(emcc --version | sed -n 1p)
EM_HAVE=
[[ $EM_LINE =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && EM_HAVE=${BASH_REMATCH[1]}
[ "$EM_HAVE" = "$EM_WANT" ] || die "emscripten ${EM_HAVE:-unknown} on PATH; build-inputs.json names $EM_WANT"

if [ -z "$WORK" ]; then
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/libves-build.XXXXXX")
    trap 'rm -rf "$WORK"' EXIT
else
    mkdir -p "$WORK"
    [ -z "$(ls -A "$WORK")" ] || die "$WORK is not empty"
fi
WORK=$(cd "$WORK" && pwd -P)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)

# fetch <component>: check out the commit build-inputs.json pins into $WORK/<component>
fetch() {
    local name=$1 dir=$WORK/$1 url commit got
    url=$(input "$name" url)
    commit=$(input "$name" commit)
    say "$name $(input "$name" version): $commit from $url"
    git init -q "$dir"
    git -C "$dir" fetch -q --depth 1 "$url" "$commit" || die "cannot fetch $name $commit from $url"
    git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
    got=$(git -C "$dir" rev-parse HEAD)
    [ "$got" = "$commit" ] || die "$name: fetched $got, expected $commit"
}

fetch liboqs
fetch openssl

cd "$ROOT"
emmake make -C WasmOQS clean
emmake make -C WasmECDH clean

say "liboqs"
emmake make -j"$JOBS" -C WasmOQS LIBOQS_SRC="$WORK/liboqs" liboqs
say "the ML-KEM engine (WasmOQS)"
emmake make -C WasmOQS LIBOQS_SRC="$WORK/liboqs"

say "OpenSSL"
emmake make -j"$JOBS" -C WasmECDH OSSL="$WORK/openssl" openssl
say "the ECDH engine (WasmECDH)"
emmake make -C WasmECDH OSSL="$WORK/openssl"

say "the bundles"
node build.js --out "$OUT"
