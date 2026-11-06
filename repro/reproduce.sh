#!/bin/bash
# Rebuild a libVES.js release from its public tag, and check every rebuilt file
# against the hashes published for that release.
#
# Usage: repro/reproduce.sh [options] <tag>            e.g. repro/reproduce.sh v3.2.4
#        repro/reproduce.sh --image <tag>              the emscripten image to run it in
#
#   --source URL     git repository that holds the tag
#                    (default: https://github.com/vesvault/libVES.git)
#   --work DIR       work directory; must be new or empty (default: a new one in $TMPDIR)
#   --expect SRC     a published hash list to compare with: a URL or a file; may repeat.
#                    Default: the release notes on GitHub, and
#                    https://ves.host/pub/libVES-<version>.sri
#   --jobs N         parallel compile jobs (default: the number of CPUs)
#   --em-cache DIR   emscripten cache to use (default: a new one in the work directory,
#                    so nothing compiled earlier on this machine goes into the rebuild)
#   --keep           keep the sources and objects (default: keep only outputs and logs)
#
# The build is the release's own: the tag's build-release.sh, which fetches
# the third-party sources at the commits the tag's build-inputs.json pins.
# 3.2.4 predates build-release.sh; for it, this script runs the same steps,
# kept below as they ran for that release. Releases before 3.2.4 are not
# covered. The comparison is this script's, not the release's.
#
# Needs bash, git, make, cmake, perl, curl, node, and emscripten (emcc,
# emcmake, emmake, emconfigure) on PATH, at the version the release names.
#
# Exit status: 0 when every published hash matches the rebuilt file, 1 when one
# differs or is missing, 2 on a usage or build error.

set -euo pipefail

SOURCE=https://github.com/vesvault/libVES.git
WORK=
EXPECT=()
JOBS=$(nproc 2>/dev/null || echo 1)
EMCACHE=
KEEP=0
IMAGE_ONLY=0

# The emscripten image for 3.2.4, which predates tools.image in build-inputs.json.
IMAGE_3_2_4=emscripten/emsdk:5.0.7@sha256:4e332f7343b6f66320bf72f7ecc01a3d9f3866721a13b0e5c7b96505d6ab148a

die() { echo "reproduce: $*" >&2; exit 2; }
say() { echo "== $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --source)   SOURCE=${2:?}; shift 2 ;;
        --work)     WORK=${2:?}; shift 2 ;;
        --expect)   EXPECT+=("${2:?}"); shift 2 ;;
        --jobs)     JOBS=${2:?}; shift 2 ;;
        --em-cache) EMCACHE=${2:?}; shift 2 ;;
        --keep)     KEEP=1; shift ;;
        --image)    IMAGE_ONLY=1; shift ;;
        -h|--help)  sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
        -*)         die "unknown option $1" ;;
        *)          break ;;
    esac
done
[ $# -eq 1 ] || die "usage: $0 [options] <tag>"
TAG=$1

# fetch_tag <dir>: the tag's tree, checked out in <dir>
fetch_tag() {
    git init -q "$1"
    git -C "$1" fetch -q --depth 1 "$SOURCE" "refs/tags/$TAG:refs/tags/$TAG" || die "cannot fetch tag $TAG from $SOURCE"
    git -C "$1" -c advice.detachedHead=false checkout -q "$TAG^{commit}"
}

# input <file> <component|tools> <field>: a field from a build-inputs.json;
# "tag" is a component's upstream tag, from its purl. Empty if absent.
input() {
    node -e '
        const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        const [name, field] = process.argv.slice(2);
        const c = name === "tools" ? j.tools : (j.components || []).find((c) => c.name === name);
        const v = !c ? null : field === "tag" ? (c.purl || "").split("@")[1] : c[field];
        if (v != null) console.log(v);
    ' "$@"
}

# image_of <tree>: the emscripten image a release names. Read with sed, not
# node, so that --image needs only git on the host that runs docker.
image_of() {
    local image
    image=$(sed -n 's/^ *"image": *"\([^"]*\)".*/\1/p' "$1/build-inputs.json" | sed -n 1p)
    if [ -z "$image" ] && [ "$(tr -d ' \r\n' < "$1/VERSION")" = 3.2.4 ]; then
        image=$IMAGE_3_2_4
    fi
    [ -n "$image" ] || die "$TAG names no emscripten image"
    echo "$image"
}

if [ "$IMAGE_ONLY" = 1 ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/libves-image.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    fetch_tag "$tmp" >&2
    image_of "$tmp"
    exit 0
fi

for tool in git make cmake perl curl node emcc emcmake emmake emconfigure; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

if [ -z "$WORK" ]; then
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/libves-repro.XXXXXX")
else
    mkdir -p "$WORK"
    [ -z "$(ls -A "$WORK")" ] || die "$WORK is not empty"
fi
WORK=$(cd "$WORK" && pwd -P)
mkdir "$WORK/logs" "$WORK/out" "$WORK/src"
export EM_CACHE=${EMCACHE:-$WORK/emcache}

cleanup() {
    [ "$KEEP" = 1 ] && return
    rm -rf "$WORK/src"
    [ -z "$EMCACHE" ] && rm -rf "$WORK/emcache"
    return 0
}
trap cleanup EXIT

# Run a step in a subshell, its output in logs/<name>.log; show the end of it
# on failure. Started with & and waited for, because a subshell run as an if
# or || condition ignores set -e and would carry on past a failed command.
step() {
    local name=$1 pid rc=0; shift
    ( "$@" ) > "$WORK/logs/$name.log" 2>&1 &
    pid=$!
    wait "$pid" || rc=$?
    if [ "$rc" != 0 ]; then
        tail -n 40 "$WORK/logs/$name.log" >&2
        die "$name failed (status $rc); full log: $WORK/logs/$name.log"
    fi
}

# --- the release source ----------------------------------------------------

say "libVES $TAG from $SOURCE"
LIBVES=$WORK/src/libVES
fetch_tag "$LIBVES"
COMMIT=$(git -C "$LIBVES" rev-parse HEAD)
TREE=$(git -C "$LIBVES" rev-parse "HEAD^{tree}")
VERSION=$(tr -d ' \r\n' < "$LIBVES/VERSION")
INPUTS=$LIBVES/build-inputs.json
[ -f "$INPUTS" ] || die "$TAG has no build-inputs.json: releases before 3.2.4 are not covered"

EM_WANT=$(input "$INPUTS" emscripten version)
EM_LINE=$(emcc --version | sed -n 1p)
EM_HAVE=
[[ $EM_LINE =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && EM_HAVE=${BASH_REMATCH[1]}
[ "$EM_HAVE" = "$EM_WANT" ] || die "emscripten ${EM_HAVE:-unknown} on PATH; $TAG was built with $EM_WANT"

# --- 3.2.4: the steps its release build ran (2026-11-04), as they were ------

# The ML-KEM engine carries one liboqs source path (an error message in
# src/common/aes/aes_c.c), so liboqs's path is mapped to the one it was built
# in. OpenSSL's configure line maps its own path.
build_3_2_4() {
    local deps=$WORK/src/deps name dir commit
    mkdir -p "$deps"
    for name in liboqs openssl; do
        dir=$deps/$name
        commit=$(input "$INPUTS" "$name" commit)
        git init -q "$dir"
        git -C "$dir" fetch -q --depth 1 "$(input "$INPUTS" "$name" url)" "$commit"
        git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
        [ "$(git -C "$dir" rev-parse HEAD)" = "$commit" ]
    done
    mkdir "$deps/liboqs/build"
    (cd "$deps/liboqs/build" &&
        emcmake cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_DIST_BUILD=OFF \
            -DCMAKE_C_FLAGS="-fmacro-prefix-map=$deps/liboqs=/usr/src/liboqs-wasm" .. &&
        emmake make -j"$JOBS" oqs)
    (cd "$deps/openssl" &&
        emconfigure ./Configure linux-generic32 no-asm no-threads no-shared no-dso \
            no-engine no-module no-legacy no-sock no-ui-console no-tests no-apps \
            no-docs no-afalgeng no-async no-secure-memory no-autoload-config \
            no-filenames no-err no-stdio no-autoalginit no-autoerrinit \
            no-aria no-argon2 no-bf no-blake2 no-camellia no-cast no-chacha no-cmac \
            no-cmp no-cms no-comp no-ct no-des no-dgram no-dh no-dsa no-ecdsa no-ecx \
            no-gost no-http no-idea no-md4 no-mdc2 no-ml-dsa no-ml-kem no-ocb \
            no-ocsp no-poly1305 no-quic no-rc2 no-rc4 no-rfc3779 no-rmd160 \
            no-scrypt no-seed no-siphash no-siv no-slh-dsa no-sm4 no-srp no-ts \
            no-whirlpool no-ssl no-tls no-dtls \
            --with-rand-seed=getrandom CC=emcc AR=emar RANLIB=emranlib -Oz -flto \
            -ffile-prefix-map="$deps/openssl"=/src/openssl -fmacro-prefix-map="$deps/openssl"=/src/openssl &&
        sed -i 's|^CROSS_COMPILE=.*|CROSS_COMPILE=|' Makefile &&
        emmake make -j"$JOBS" build_generated libcrypto.a)
    emmake make -C "$LIBVES/WasmOQS" LIBOQS="$deps/liboqs/build"
    emmake make -C "$LIBVES/WasmECDH" OSSL="$deps/openssl"
    (cd "$LIBVES" && node build.js --out "$WORK/out")
}

# --- the build ----------------------------------------------------------------

if [ -f "$LIBVES/build-release.sh" ]; then
    HOW="the release's own build-release.sh"
    BUILD=(bash "$LIBVES/build-release.sh" --work "$WORK/src/deps" --out "$WORK/out" --jobs "$JOBS")
elif [ "$VERSION" = 3.2.4 ]; then
    HOW="the 3.2.4 release build's steps, in this script"
    BUILD=(build_3_2_4)
else
    die "$TAG has no build-release.sh: releases before 3.2.4 are not covered"
fi
say "build, with $HOW"
step build "${BUILD[@]}"

# --- compare ----------------------------------------------------------------

sri() {
    node -e '
        const c = require("crypto"), fs = require("fs");
        console.log("sha384-" + c.createHash("sha384").update(fs.readFileSync(process.argv[1])).digest("base64"));
    ' "$1"
}

[ ${#EXPECT[@]} -gt 0 ] || EXPECT=(
    "https://api.github.com/repos/vesvault/libVES/releases/tags/$TAG"
    "https://ves.host/pub/libVES-$VERSION.sri"
)

{
    echo
    echo "libVES $TAG (version $VERSION), built with $HOW"
    printf '%-11s %-8s %s  (tree %s, from %s)\n' libVES "$VERSION" "$COMMIT" "$TREE" "$SOURCE"
    # Each pinned component, and whether its upstream tag still names the
    # pinned commit (for an annotated tag, the commit is on the ^{} line).
    for name in $(node -e '
            const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
            for (const c of j.components) if (c.commit) console.log(c.name);
        ' "$INPUTS"); do
        url=$(input "$INPUTS" "$name" url)
        commit=$(input "$INPUTS" "$name" commit)
        tag=$(input "$INPUTS" "$name" tag)
        upstream=$(git ls-remote "$url" "refs/tags/$tag" "refs/tags/$tag^{}" |
            awk '$2 ~ /\^\{\}$/ { p = $1 } $2 !~ /\^\{\}$/ { t = $1 } END { print (p != "" ? p : t) }') || upstream=
        if [ "$upstream" = "$commit" ]; then note="tag $tag"; else note="tag $tag now names ${upstream:-nothing}"; fi
        printf '%-11s %-8s %s  (%s)\n' "$name" "$(input "$INPUTS" "$name" version)" "$commit" "$note"
    done
    node_want=$(input "$INPUTS" tools node)
    node_have=$(node --version | sed 's/^v//')
    printf '%-11s %s\n' emscripten "$EM_LINE"
    printf '%-11s %s\n' node "v$node_have$( [ -z "$node_want" ] || [ "$node_have" = "$node_want" ] || echo " (the release names $node_want)")"
    printf '%-11s %s\n' cmake "$(cmake --version | sed -n 1p)"
    printf '%-11s %s\n' host "$(uname -srm)${REPRO_IMAGE:+, image $REPRO_IMAGE}"
} | tee "$WORK/summary.txt"

declare -A MATCHED=()
FAIL=0
for src in "${EXPECT[@]}"; do
    echo | tee -a "$WORK/summary.txt"
    echo "Published in $src:" | tee -a "$WORK/summary.txt"
    if [ -f "$src" ]; then
        text=$(cat "$src")
    else
        text=$(curl -fsSL "$src") || { echo "  MISSING   could not fetch it" | tee -a "$WORK/summary.txt"; FAIL=1; continue; }
    fi
    lines=$(printf '%s\n' "$text" | grep -oE 'sha384-[A-Za-z0-9+/]{64}  [A-Za-z0-9._/-]+' | sort -u || true)
    if [ -z "$lines" ]; then
        echo "  MISSING   no hashes in it" | tee -a "$WORK/summary.txt"
        FAIL=1
        continue
    fi
    while read -r want file; do
        if [ ! -f "$WORK/out/$file" ]; then
            echo "  MISSING   $file (not rebuilt)" | tee -a "$WORK/summary.txt"
            FAIL=1
            continue
        fi
        got=$(sri "$WORK/out/$file")
        if [ -n "$got" ] && [ "$got" = "$want" ]; then
            echo "  match     $file  $got" | tee -a "$WORK/summary.txt"
            MATCHED[$file]=1
        else
            { echo "  DIFFERS   $file"; echo "            published $want"; echo "            rebuilt   ${got:-nothing}"; } | tee -a "$WORK/summary.txt"
            FAIL=1
        fi
    done <<< "$lines"
done

# Every file the rebuild lists in its own .sri must have been matched somewhere.
while read -r _ file; do
    [ -n "${MATCHED[$file]:-}" ] || { echo "  UNCHECKED $file (no published hash matched it)" | tee -a "$WORK/summary.txt"; FAIL=1; }
done < "$WORK/out/libVES-$VERSION.sri"

echo | tee -a "$WORK/summary.txt"
if [ "$FAIL" = 0 ]; then
    echo "REPRODUCED: libVES $TAG, ${#MATCHED[@]} files byte for byte as published." | tee -a "$WORK/summary.txt"
else
    echo "NOT REPRODUCED: libVES $TAG differs from what was published (see above)." | tee -a "$WORK/summary.txt"
fi
echo "Outputs: $WORK/out  Logs: $WORK/logs  Summary: $WORK/summary.txt"
exit "$FAIL"
