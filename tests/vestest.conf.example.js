// Preferred conf format is the libVES.c-style shell conf at ~/.vestest.conf:
//
//     EMAIL=user@domain.com
//     EMAIL2=user2@domain.com         # optional, only for 02-share / 04-domain
//     DOM=demo                        # optional, defaults to 'demo'
//     DOM2=...                        # optional, only for 04-domain — see below
//     apiUrl=https://api.example.test/v1/
//     pollUrl=https://poll.example.test/v1/
//     wwwUrl=https://www.example.test/
//
// apiUrl is REQUIRED, and the runner refuses to start without it: the tests
// unlock vaults and write and delete items, and without apiUrl libVES sends
// all of it to its default, the PRODUCTION API https://api.ves.host/v1/.
// pollUrl and wwwUrl default to production too (https://poll.ves.host/v1/,
// https://www.vesvault.com/), so they are required as well unless apiUrl is
// the production API.
//
// To run against PRODUCTION on purpose, name it:
//     apiUrl=https://api.ves.host/v1/
// and leave pollUrl and wwwUrl out (or name them too).
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
    apiUrl: 'https://api.example.test/v1/',     // required, see above
    pollUrl: 'https://poll.example.test/v1/',
    wwwUrl: 'https://www.example.test/',
};
