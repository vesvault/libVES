// Preferred conf format is the libVES.c-style shell conf at ~/.vestest.conf:
//
//     EMAIL=user@domain.com
//     EMAIL2=user2@domain.com         # optional, only for 02-share / 04-domain
//     DOM=demo                        # optional, defaults to 'demo'
//     DOM2=...                        # optional, only for 04-domain — see below
//     apiUrl=https://api.ves.host/v1/ # optional
//
// DOM2 must point at an existing second domain. The JS lib doesn't yet
// support the libVES.c primary,elevate,save flow that auto-creates a fresh
// domain on first use (depends on VESlocker, not wired into Node), so
// pre-create the domain once via the C CLI:
//     ves -A $EMAIL -a //$DOM2/$EMAIL/ -n -E primary,elevate,save
//
// VESkeys are NOT in the conf. tests/node.inc.js wires libVES.KeyStore to
// the libVES.c-compatible keydir at $VES_KEYSTORE (or ~/.ves/), so the
// `ves` CLI and these tests share key storage. On a fresh keydir, the
// cross-device /api/msg sync runs and prompts for a PIN at the terminal.
//
// This JS form is still honored (copy to tests/vestest.conf.js or set
// $VESTEST_CONF) for back-compat:
module.exports = {
    EMAIL: 'user@domain.com',
    DOM: 'demo',
    // EMAIL2: 'user2@domain.com',
    // DOM2: 'second-domain',
    // apiUrl: 'https://api.ves.host/v1/',
};
