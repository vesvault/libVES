# Contributing to libVES

Thanks for your interest. libVES is the official VESvault JavaScript library
(published on npm as [`libves`](https://www.npmjs.com/package/libves)) — it's
security-critical software, backed by a hosted service, that real users trust
with their data. The guidelines below keep contributions safe to merge.

## Reporting security vulnerabilities

**Do not open a public issue, pull request, or discussion for security problems.**
Follow [SECURITY.md](SECURITY.md) — email **security@vesvault.com**. This is the
single most important rule here.

## Bugs and small fixes

Bug reports and small, focused fixes are welcome via issues and pull requests:

- Search existing issues first.
- For a bug, include the `libves` version (`npm ls libves`) or commit, the
  environment (browser + version, or Node version), how you load the library
  (npm, `<script>`/CDN, or a bundler), and a minimal reproduction. **Redact any
  real VESkeys, tokens, or private keys.**
- Keep PRs focused; one logical change per PR is easiest to review.

## Larger changes — start with an issue

Because this library interoperates with a hosted protocol, changes to
**cryptography, the public API surface, or the wire protocol should start as an
issue** before you write code. We can't always merge changes that affect the
protocol or the service, and a short discussion up front saves wasted effort.

## Editing source and building

The shipped bundles are **generated** — don't edit them. Source lives in the
per-module `libVES.*.js` files (concatenated in the order listed in
[`build.js`](build.js)); the build outputs (`libVES.js`, `libVES.node.js`, the
version-stamped `libVES-<version>.js`, and the minified variants) are git-ignored
and produced by the build:

```sh
node build.js            # browser + Node bundles
node build.js --minify   # also writes the *.min.js variants (needs `npm i -D terser`)
```

Requires **Node 18+** (the library uses the built-in `fetch`). The post-quantum
(ML-KEM via liboqs) and ECDH primitives are compiled to WebAssembly from
`WasmOQS/` and `WasmECDH/` with the emscripten toolchain; that glue is **not**
committed, so a full `node build.js` needs those wasm artifacts present. Most
contributions don't require rebuilding the wasm — see the `Wasm*/Makefile`
comments if yours does.

Before opening a PR, make sure every source module still parses:

```sh
node --check libVES*.js build.js
```

## CI and tests

CI runs that same syntax check on Node 18/20/22 and validates the npm manifest.
It does **not** run `tests/`: that suite drives the live VES API and needs two
real, synced VES accounts (see `tests/vestest.conf.example.js`). To run it
locally, copy your account settings into a `vestest.conf.js` and run the scripts
in [`tests/`](tests/) (`node tests/01-item.js`, …) or open `tests/index.html` in
a browser.

## Style

Match the style of the surrounding code — indentation, naming, and bracing.
Please don't reformat unrelated code in a PR.

## Licensing

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).
