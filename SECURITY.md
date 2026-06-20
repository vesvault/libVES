# Security Policy

libVES (JavaScript) is end-to-end encryption software — the confidentiality of real users'
data depends on it. We take vulnerability reports seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for security problems.**

Email **security@vesvault.com** with:

- a description of the issue and its impact,
- steps to reproduce (a proof-of-concept if you have one),
- the affected version(s) or commit, and the environment (browser / Node version, build).

If you need to share sensitive details, say so in your first message and we'll arrange an
encrypted channel.

We aim to **acknowledge** a report within 3 business days and to share an initial
**assessment** within 10 business days. We'll keep you updated and coordinate a disclosure
timeline with you — please give us a reasonable window to ship a fix before going public
(typically up to 90 days).

## Scope

**In scope:** the libVES JavaScript library in this repository — cryptographic
correctness, key and VESkey handling, and anything that could expose plaintext, private
keys, or VESkeys to a party that should not have them.

**Out of scope here:** the hosted VESvault service/API (email the same address — we route
it), and bugs in third-party dependencies — please report those upstream as well, though
we're glad to hear about them.

## Design & threat model

The recovery design and its explicit, documented threat model live in the libVES.c
repository — [`doc/VESrecovery.md`](https://github.com/vesvault/libVES.c/blob/master/doc/VESrecovery.md)
and [`doc/org-key-custody.md`](https://github.com/vesvault/libVES.c/blob/master/doc/org-key-custody.md)
— and at <https://ves.host>. Findings that contradict those claims are especially valuable.

## Supported versions

Security fixes target the latest released version. Older versions are handled case by
case.
