# libVES 3.2.4: the release build as it ran on 2026-11-04. Sourced by
# repro/reproduce.sh, which has already fetched each component in COMPONENTS
# at the commit build-inputs.json pins, into $WORK/src/<component>.
#
# - WasmOQS, the ML-KEM engine both bundles embed, links liboqs 0.13.0. That
#   liboqs was built on 2026-05-26 in /usr/src/liboqs-wasm/build, and one of
#   its source paths is compiled into the engine (an error message in
#   src/common/aes/aes_c.c), so the rebuild maps its own path to that one. The
#   engine itself was linked on 2026-06-22 and has not changed since 3.1.0.
# - WasmECDH, the lazy ECDH engine (embedded in the Node bundle), links
#   OpenSSL 3.5.9's libcrypto, configured as WasmECDH/Makefile says; its prefix
#   maps keep the build path out.

# The emscripten image the GitHub workflow runs this release in: 5.0.7, as
# build-inputs.json names, pinned by digest.
IMAGE=emscripten/emsdk:5.0.7@sha256:4e332f7343b6f66320bf72f7ecc01a3d9f3866721a13b0e5c7b96505d6ab148a

COMPONENTS=(liboqs openssl)

build_liboqs() {
    local src=$1
    mkdir "$src/build"
    cd "$src/build"
    emcmake cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_DIST_BUILD=OFF \
        -DCMAKE_C_FLAGS="-fmacro-prefix-map=$src=/usr/src/liboqs-wasm" ..
    emmake make -j"$JOBS" oqs
}

build_openssl() {
    local src=$1
    cd "$src"
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
        -ffile-prefix-map="$src"=/src/openssl -fmacro-prefix-map="$src"=/src/openssl
    sed -i 's|^CROSS_COMPILE=.*|CROSS_COMPILE=|' Makefile
    emmake make -j"$JOBS" build_generated libcrypto.a
}

build_engines() {
    local tree=$1
    emmake make -C "$tree/WasmOQS" LIBOQS="$WORK/src/liboqs/build"
    emmake make -C "$tree/WasmECDH" OSSL="$WORK/src/openssl"
}

# SHA-256 of intermediate files from the release build, under $WORK/src.
# Reported, not required: only the published hashes decide.
declare -A KNOWN_SHA256=(
    [liboqs/build/lib/liboqs.a]=3cfdd9171c1f4a8ae5ab4e3f287886ba24c4552d3382bbdf02ad1878cfdff5ce
    [openssl/libcrypto.a]=4a286f213117ba792050751861b807e82a371424cd57511c3f1659993a341c59
    [libVES/WasmOQS/WasmOQS.single.js]=8aa1061975441fd0090f2a86e828d637345dd98279a06a1cdca25402df99f52d
    [libVES/WasmECDH/WasmECDH.wasm]=df1a3ac2a72632fdc745db1d2facbf0e82b6c95d222340fb96c870c60622c28b
    [libVES/WasmECDH/WasmECDH.js]=6def04eca3ce7c0a0cee4762cfb5decc08bb0f04df78ad2a1557666b46d90184
    [libVES/WasmECDH/WasmECDH.single.js]=629527e40604fc807f21a7370ff4233894b0a01cd1fad05d40c8462445adcc00
)
