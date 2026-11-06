#!/bin/bash
# Rebuild a libVES.js release from its public tag and the inputs it pins, and
# check every rebuilt file against the hashes published for that release.
#
# Usage: repro/reproduce.sh [options] <tag>            e.g. repro/reproduce.sh v3.2.4
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
# Needs bash, git, make, cmake, perl, curl, node, and emscripten (emcc, emcmake,
# emmake) on PATH, at the emscripten version the release's build-inputs.json
# names. repro/recipes/<version>.sh holds the build steps of each release.
#
# Exit status: 0 when every published hash matches the rebuilt file, 1 when one
# differs or is missing, 2 on a usage or build error.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE=https://github.com/vesvault/libVES.git
WORK=
EXPECT=()
JOBS=$(nproc 2>/dev/null || echo 1)
EMCACHE=
KEEP=0

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
        -h|--help)  sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
        -*)         die "unknown option $1" ;;
        *)          break ;;
    esac
done
[ $# -eq 1 ] || die "usage: $0 [options] <tag>"
TAG=$1

for tool in git make cmake perl curl node emcc emcmake emmake; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

if [ -z "$WORK" ]; then
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/libves-repro.XXXXXX")
else
    mkdir -p "$WORK"
    [ -z "$(ls -A "$WORK")" ] || die "$WORK is not empty"
fi
WORK=$(cd "$WORK" && pwd)
mkdir "$WORK/logs" "$WORK/out"
export EM_CACHE=${EMCACHE:-$WORK/emcache}

cleanup() {
    [ "$KEEP" = 1 ] && return
    rm -rf "$WORK/src"
    [ -z "$EMCACHE" ] && rm -rf "$WORK/emcache"
    return 0
}
trap cleanup EXIT

# Run a build step in a subshell, its output in logs/<name>.log; show the end of
# it on failure. Started with & and waited for, because a subshell run as an if
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
mkdir "$WORK/src"
LIBVES=$WORK/src/libVES
git init -q "$LIBVES"
git -C "$LIBVES" fetch -q --depth 1 "$SOURCE" "refs/tags/$TAG:refs/tags/$TAG" || die "cannot fetch tag $TAG"
COMMIT=$(git -C "$LIBVES" rev-parse "$TAG^{commit}")
TREE=$(git -C "$LIBVES" rev-parse "$TAG^{tree}")
git -C "$LIBVES" -c advice.detachedHead=false checkout -q "$COMMIT"
VERSION=$(tr -d ' \r\n' < "$LIBVES/VERSION")
RECIPE=$HERE/recipes/$VERSION.sh
[ -f "$RECIPE" ] || die "no recipe for $VERSION ($RECIPE)"
INPUTS=$LIBVES/build-inputs.json
[ -f "$INPUTS" ] || die "$TAG has no build-inputs.json"

# input <component> <field>: a field of a component in build-inputs.json;
# "tag" is the upstream tag, from the purl.
input() {
    node -e '
        const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        const [name, field] = process.argv.slice(2);
        const c = name === "tools" ? j.tools : j.components.find((c) => c.name === name);
        const v = !c ? null : field === "tag" ? (c.purl || "").split("@")[1] : c[field];
        if (v == null) process.exit(3);
        console.log(v);
    ' "$INPUTS" "$1" "$2" || die "build-inputs.json has no $2 for $1"
}

# --- the toolchain ----------------------------------------------------------

# (sed -n 1p rather than head: head closing the pipe early can fail the
# command under pipefail.)
EM_WANT=$(input emscripten version)
EM_LINE=$(emcc --version | sed -n 1p)
EM_HAVE=
[[ $EM_LINE =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && EM_HAVE=${BASH_REMATCH[1]}
[ "$EM_HAVE" = "$EM_WANT" ] || die "emscripten ${EM_HAVE:-unknown} on PATH; $TAG was built with $EM_WANT"
NODE_WANT=$(input tools node)
NODE_HAVE=$(node --version | sed 's/^v//')

# --- the pinned inputs --------------------------------------------------------

# fetch <component>: check out the pinned commit into src/<component>.
fetch() {
    local name=$1 dir=$WORK/src/$1 url commit tag got upstream
    url=$(input "$name" url)
    commit=$(input "$name" commit)
    tag=$(input "$name" tag)
    git init -q "$dir"
    git -C "$dir" fetch -q --depth 1 "$url" "$commit" || die "cannot fetch $name $commit from $url"
    git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
    got=$(git -C "$dir" rev-parse HEAD)
    [ "$got" = "$commit" ] || die "$name: fetched $got, expected $commit"
    # The upstream tag should still name the pinned commit (for an annotated
    # tag, the commit is on the peeled ^{} line). The build uses the commit
    # either way.
    upstream=$(git ls-remote "$url" "refs/tags/$tag" "refs/tags/$tag^{}" |
        awk '$2 ~ /\^\{\}$/ { p = $1 } $2 !~ /\^\{\}$/ { t = $1 } END { print (p != "" ? p : t) }') || upstream=
    if [ "$upstream" = "$commit" ]; then
        printf '%-11s %-8s %s  (tag %s)\n' "$name" "$(input "$name" version)" "$commit" "$tag" >> "$WORK/inputs.txt"
    else
        printf '%-11s %-8s %s  (tag %s now names %s)\n' "$name" "$(input "$name" version)" "$commit" "$tag" "${upstream:-nothing}" >> "$WORK/inputs.txt"
    fi
}

declare -A KNOWN_SHA256=()
# shellcheck source=/dev/null
. "$RECIPE"

: > "$WORK/inputs.txt"
for c in "${COMPONENTS[@]}"; do
    say "$c"
    fetch "$c"
    step "build-$c" "build_$c" "$WORK/src/$c"
done

say "engines"
step engines build_engines "$LIBVES"

say "bundles"
step bundles bash -c 'cd "$1" && node build.js --out "$2"' _ "$LIBVES" "$WORK/out"

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
    echo "libVES $TAG (version $VERSION)"
    printf '%-11s %-8s %s  (tree %s, from %s)\n' libVES "$VERSION" "$COMMIT" "$TREE" "$SOURCE"
    cat "$WORK/inputs.txt"
    printf '%-11s %s\n' emscripten "$EM_LINE"
    printf '%-11s %s\n' node "v$NODE_HAVE$( [ "$NODE_HAVE" = "$NODE_WANT" ] || echo " (the release names $NODE_WANT)")"
    printf '%-11s %s\n' cmake "$(cmake --version | sed -n 1p)"
    printf '%-11s %s\n' host "$(uname -srm)${REPRO_IMAGE:+, image $REPRO_IMAGE}"
    [ ${#KNOWN_SHA256[@]} -gt 0 ] || exit 0
    echo
    echo "Intermediate files against the release build (for diagnosis only):"
    for f in "${!KNOWN_SHA256[@]}"; do
        if [ -f "$WORK/src/$f" ]; then
            got=$(sha256sum "$WORK/src/$f" | cut -d' ' -f1)
            [ "$got" = "${KNOWN_SHA256[$f]}" ] && r=same || r=different
        else
            r=missing
        fi
        printf '  %-9s %s\n' "$r" "$f"
    done | sort -k2
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
