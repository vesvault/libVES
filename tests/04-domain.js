/*
 * 04-domain.js — cross-domain operations.
 * Mirrors libVES.c/tests/04-domain (partial port).
 *
 * The C test creates a brand-new "experimental" domain via primary-user
 * elevated auth (`-A $EMAIL -E primary,elevate,save`). The browser port
 * reaches the same bootstrap through libVES.subtle(...).unlock(): the
 * fresh ves has no token, VES.unlock() rejects, Vault.unlock() falls to
 * the delegate branch and opens the VESvault popup with domain=DOM2 —
 * the server-side primary,elevate flow auto-creates the experimental
 * domain on first auth. Each DOM2 vault (EMAIL, EMAIL2) needs its own
 * popup; the user authorizes EMAIL first, then EMAIL2.
 *
 * Node has no document, so unlock() defaults to keystore mode and can't
 * drive that bootstrap — the test self-skips there. fillConf only fills
 * conf.DOM2 in the browser to enforce the split.
 *
 * Requires t.ves2 (a second authorized user) regardless of platform.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('04-domain', async function (t) {
    if (!t.needVes2('04-domain requires a second authorized user')) return;
    if (!t.conf.DOM2) {
        t.info('SKIPPED: conf.DOM2 not set. In Node the JS lib cannot bootstrap ' +
            'a fresh domain (delegate-mode unlock needs a DOM, keystore-mode ' +
            'cannot drive primary,elevate,save). Pre-create a second domain ' +
            'via the C CLI:\n' +
            '    ves -A $EMAIL -a //$DOM2/$EMAIL/ -n -E primary,elevate,save\n' +
            'then set DOM2=<that-domain> in ~/.vestest.conf.');
        return;
    }

    var ref = libVES.Vault.toRef('//' + t.conf.DOM2 + '/dom2-obj-' + t.conf.NONCE);

    // Bootstrap a fresh ves for each DOM2 identity. libVES.subtle() builds
    // a standalone libVES + Vault pair; .unlock() in the browser falls
    // through VES.unlock() into delegate and triggers the popup. The
    // popup's domain=DOM2 query tells V to run primary,elevate,save,
    // which auto-creates the experimental domain on first auth.
    t.head('Bootstrap DOM2 vault for ' + t.conf.EMAIL + ' (VESvault popup expected)');
    var dom2VaultEmail = libVES.subtle(vestest.libVESoptns(t.conf, { domain: t.conf.DOM2, externalId: t.conf.EMAIL }));
    await t.run('unlock dom2/' + t.conf.EMAIL, async function () {
        await dom2VaultEmail.unlock();
    });

    t.head('Bootstrap DOM2 vault for ' + t.conf.EMAIL2 + ' (VESvault popup expected)');
    var dom2VaultEmail2 = libVES.subtle(vestest.libVESoptns(t.conf, { domain: t.conf.DOM2, externalId: t.conf.EMAIL2 }));
    await t.run('unlock dom2/' + t.conf.EMAIL2, async function () {
        await dom2VaultEmail2.unlock();
    });

    t.head('Creating item in DOM2, shared with self + cross-domain (DOM)');
    await t.run('put item with cross-domain share', async function () {
        await dom2VaultEmail.item(ref).put('cross-domain-test', [
            { domain: t.conf.DOM2, externalId: t.conf.EMAIL },
            { domain: t.conf.DOM,  externalId: t.conf.EMAIL },
        ]);
    });

    t.head('Retrieving via DOM2 path');
    var got;
    await t.run('get via dom2', async function () { got = await dom2VaultEmail.item(ref).get(); });
    await t.expect('value', 'cross-domain-test', got);

    t.head('Retrieving via DOM (cross-domain) path');
    var domVault = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL }, t.ves);
    var refInDom = libVES.Vault.toRef('//' + t.conf.DOM2 + '/dom2-obj-' + t.conf.NONCE); // same external
    await t.run('get via dom cross-domain', async function () { got = await domVault.item(refInDom).get(); });
    await t.expect('value', 'cross-domain-test', got);

    t.head('Sharing the item with ' + t.conf.EMAIL2 + ' in DOM2');
    await t.run('share with email2 dom2', async function () {
        await dom2VaultEmail.item(ref).share([
            { domain: t.conf.DOM2, externalId: t.conf.EMAIL },
            { domain: t.conf.DOM2, externalId: t.conf.EMAIL2 },
        ]);
    });

    t.head('Retrieving via ' + t.conf.EMAIL2 + ' in DOM2');
    await t.run('get via email2 dom2', async function () { got = await dom2VaultEmail2.item(ref).get(); });
    await t.expect('value', 'cross-domain-test', got);

    t.head('Cleanup');
    await t.run('delete item', async function () { await dom2VaultEmail.item(ref).delete(); });
}, { needsVes2: true });

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['04-domain']);
