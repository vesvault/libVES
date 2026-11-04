```
          ___       ___
         /   \     /   \    VESvault
         \__ /     \ __/    Encrypt Everything without fear of losing the Key
            \\     //                   https://vesvault.com  https://ves.host
             \\   //
     ___      \\_//
    /   \     /   \         libVES:                      VESvault API library
    \__ /     \ __/
       \\     //
        \\   //
         \\_//              - Key Management and Exchange
         /   \              - Item Encryption and Sharing
         \___/              - VESrecovery™
```

# libVES.js

[![CI](https://github.com/vesvault/libVES/actions/workflows/ci.yml/badge.svg)](https://github.com/vesvault/libVES/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/libves)](https://www.npmjs.com/package/libves)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**End-to-end encryption for the browser and Node — that you can actually recover from.**

The official VESvault JavaScript library. It does client-side end-to-end encryption
with three things most E2E stacks leave you to build (or skip) yourself:

- **End-to-end encryption at rest** — data is encrypted in the browser/Node; the server
  only ever stores ciphertext.
- **Secure item sharing** — share an encrypted value with another user by reference;
  they decrypt it with *their* key, no shared password.
- **VESrecovery™** — recover from a lost key without weakening the encryption.

Also on npm: [`libves`](https://www.npmjs.com/package/libves).

## Why VES exists

True end-to-end encryption has a brutal failure mode: **lose the key and the data is
gone forever.** That single problem is why most products quietly fall back to
server-side encryption, where the provider can read everything.

VES makes the encryption keys themselves recoverable — through other devices and people
you trust — **without the VESvault service ever seeing your keys or your plaintext.**
You get real end-to-end encryption *and* a way back in when a device is lost.

> **Is VESrecovery a backdoor?** No. Recovery re-shares an encrypted key along a trust
> chain *you* define (your other devices, designated recovery contacts); the server only
> ever holds ciphertext it cannot decrypt. The mechanism — and its honest trade-offs —
> are written up in the [VESrecovery design doc](https://github.com/vesvault/libVES.c/blob/master/doc/VESrecovery.md)
> and at <https://ves.host>. We welcome scrutiny of it.

## Quick start

```js
// Open a vault in the shared `demo` domain (use your own identity in place of
// me@example.com). unlock() runs your app's auth: the VES authorization popup
// in the browser, or the local key store under Node — see the docs for options.
const vault = libVES.subtle('//demo/me@example.com');
await vault.unlock();

// Items are addressed by URI. Encrypt + store, then read it back:
await vault.item('//demo/note-1').put('hello');
console.log(await vault.item('//demo/note-1').get());   // -> "hello"

// Share with another VES user — they decrypt with their own key
// (their vault must already exist):
await vault.item('//demo/note-1').share(['//demo/friend@example.com']);
```

`put()` / `get()` / `share()` handle the encryption, key exchange, and API calls for
you. Full API reference: <https://ves.host/docs/libVES-subtle>.

> **Domains.** A VES *domain* (the `demo` above) namespaces vaults and items. It may
> mirror a DNS domain, but it must be registered in VES first. Two kinds work without
> registration: **`demo`** — a shared sandbox, used in the examples here — and **`x-…`**
> — experimental domains (any name beginning with `x-`) that are created automatically
> on first use, giving you a private namespace to build against. Any other (real DNS)
> domain returns an error until it is registered through VES Enterprise.

Runnable end-to-end examples live in [`tests/`](tests/) (`01-item.js`, `02-share.js`,
…) and can be run with `node tests/01-item.js` or opened in the browser via
`tests/index.html`.

## Install

```sh
npm install libves
```

Or load a released bundle with a `<script>` tag, pinned by its Subresource Integrity hash:

```html
<script src="https://ves.host/pub/libVES-<version>.js"
        integrity="sha384-<hash>"
        crossorigin="anonymous"></script>
```

Each release publishes its hashes in the GitHub release notes and at
`https://ves.host/pub/libVES-<version>.sri`. Take the hash from the release notes: a hash
fetched from the same server as the file proves nothing if that server is compromised.
To self-host the file, check it against the published hash first:

```sh
openssl dgst -sha384 -binary libVES-<version>.js | openssl base64 -A
```

One hash covers the whole client. The ML-KEM engine is embedded in the bundle. The ECDH
engine, fetched only when WebCrypto lacks a curve, comes from
`https://ves.host/pub/wasm-<version>/` and is checked against hashes the bundle carries;
to self-host it, copy that directory and set `WasmECDHinit.baseUrl` to it. It is OpenSSL's
libcrypto compiled to WebAssembly, so it handles every named curve OpenSSL does, under the
same names libVES.c uses.

Each release also publishes its SBOM (CycloneDX), `libVES-<version>.cdx.json`, next to
the hashes: the third-party code compiled into the engines, with versions, commits and
licenses. The npm package carries it as `libVES.cdx.json`.

- Pin a version-stamped file, never the unversioned `libVES.js`.
- The bundle starts with a UTF-8 byte-order mark, which makes browsers read it as UTF-8
  whatever the page encoding. Keep it if you re-bundle or minify, or serve the file with
  `charset=utf-8`.
- A page with a Content-Security-Policy needs `'wasm-unsafe-eval'` in `script-src`.

Or build from source (see below).

## Building

- `node build.js` — produces version-stamped `libVES-<version>.js` (browser) and
  `libVES-<version>.node.js` (Node) for CDN/`<script>` delivery, plus stable `libVES.js`
  and `libVES.node.js` (the npm `browser` / `main` entry points), the lazy ECDH engine
  laid out as served (`wasm-<version>/`), `libVES-<version>.sri` with the SRI hash of
  every version-stamped file, and `libVES-<version>.cdx.json`, the SBOM, written from
  [`build-inputs.json`](build-inputs.json). Cross-platform; `Makefile.bat` and `make all`
  both call it.
- `node build.js --minify` — also writes `libVES-<version>.min.js` and `libVES.min.js`
  (requires `npm i -D terser`).
- Requires **Node 18+** (uses the built-in `fetch`).

### Wasm builds

Post-quantum (ML-KEM via liboqs) and ECDH (via OpenSSL) primitives are compiled to
WebAssembly. See the comments in [`WasmOQS/Makefile`](WasmOQS/Makefile) and
[`WasmECDH/Makefile`](WasmECDH/Makefile); the pinned versions and build options are in
[`build-inputs.json`](build-inputs.json). The ECDH engine's tests are in
[`WasmECDH/test/`](WasmECDH/test/).

## Post-quantum

The library supports post-quantum key exchange (ML-KEM / Kyber and other KEMs) via the
`libVES.Algo.OQS` module and the WasmOQS build. This matters today: "harvest now,
decrypt later" means data exchanged with classical-only keys can be captured now and
broken once quantum hardware arrives.

## Real-time events

`libVES.Vault` and `libVES.Item` are event targets: call `.start()` and add listeners to
react to activity as it happens — an item shared with you, a key granted or revoked, a new
session opened.

```js
vault.addEventListener('itemadd', (e) => {
    console.log('shared with me:', e.detail.item.uri());
});
vault.start();          // begin watching; vault.stop() to end
```

Useful for live UI updates, notifications, and reacting to shares and revocations without
polling your own state. (`libVES.Watch` is the lower-level long-poll primitive underneath.)

## Pricing & terms

VES has a **free tier**; paid usage is **priced by volume**. The library is free and
open source under the Apache License 2.0. See current terms and pricing at
<https://ves.host/terms_conditions> and <https://vesvault.com>.

## Contributing

Bug reports and small, focused fixes are welcome via issues and pull requests. Because
this is security-critical software backed by a hosted service, larger changes — new
cryptography, API-surface or protocol changes — should **start with an issue** before you
write code; we can't always merge changes that affect the protocol or the service. See
[CONTRIBUTING.md](CONTRIBUTING.md) for build, syntax-check, and test details, and our
[Code of Conduct](CODE_OF_CONDUCT.md).

Security issues are different: **please don't open a public issue or PR** — follow
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Copyright © 2017–2026
VESvault Corp.

## Links

- Documentation — <https://ves.host>
- JavaScript API reference — <https://ves.host/docs/libVES-subtle>
- npm — <https://www.npmjs.com/package/libves>
- C library & `ves` CLI — <https://ves.host/docs/libVES-c>
