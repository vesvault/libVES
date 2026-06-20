/*
 * 02-share.js — item sharing between two authorized users.
 * Mirrors libVES.c/tests/02-share.
 *
 * Requires t.ves2 (a second authorized user). In Node set
 * conf.EMAIL2 + conf.VESKEY2; in the browser, click "Authorize 2nd user".
 *
 * The C test exercises many corner cases (section-vault read-only sessions,
 * cross-section sharing rules, temp-vault auto-creation, admin grant/revoke).
 * This port focuses on the user-to-user sharing path that's cleanly exposed
 * via Item.put(value, shares) / Item.share() / Item.remove() on the
 * secondary-vault JS API. Section-vault scenarios from the C test are noted
 * but not ported — the keystore-based section sessions don't translate
 * directly to the delegate-flow secondary vaults.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('02-share', async function (t) {
    if (!t.needVes2('02-share requires a second authorized user')) return;

    var ref = libVES.Vault.toRef(t.conf.OBJ);
    var ref2 = libVES.Vault.toRef(t.conf.OBJ2);
    var ref3 = libVES.Vault.toRef(t.conf.OBJ3);
    var vault1 = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL }, t.ves);
    var vault2 = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL2 }, t.ves2);

    var share1 = { domain: t.conf.DOM, externalId: t.conf.EMAIL };
    var share2 = { domain: t.conf.DOM, externalId: t.conf.EMAIL2 };
    var admin2 = { domain: '.admin', externalId: t.conf.EMAIL2 };
    var admin1 = { domain: '.admin', externalId: t.conf.EMAIL };

    t.head('Creating item ' + t.conf.OBJ + ' owned by ' + t.conf.EMAIL);
    await t.run('put item', async function () {
        await vault1.item(ref).put('test', [share1]);
    });

    t.head('Sharing ' + t.conf.OBJ + ' with ' + t.conf.EMAIL2);
    await t.run('share with email2', async function () {
        await vault1.item(ref).share([share1, share2]);
    });

    t.head('Retrieving ' + t.conf.OBJ + ' through ' + t.conf.EMAIL2);
    var got;
    await t.run('get via email2', async function () { got = await vault2.item(ref).get(); });
    await t.expect('value', 'test', got);

    t.head('Overwriting ' + t.conf.OBJ + ' through ' + t.conf.EMAIL2 + ' — error expected (no admin)');
    await t.run('overwrite without admin rejects', async function () {
        var threw = null;
        try { await vault2.item(ref).put('test2'); } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    t.head('Granting admin on ' + t.conf.OBJ + ' to ' + t.conf.EMAIL2);
    await t.run('grant admin', async function () {
        await vault1.item(ref).share([share1, share2, admin2]);
    });

    // If EMAIL2's session can't yet mint a new secondary VaultKey for
    // themselves (the lib throws "Only a primary user session can create a
    // secondary VaultKey for themselves"), re-authorize ves2 using whatever
    // mechanism the runtime registered — vestest.unlockFn in Node (which is
    // libVES.KeyStore-backed), or ves2.delegate() in the browser where no
    // VESkey is on hand.
    t.head('Overwriting ' + t.conf.OBJ + ' through ' + t.conf.EMAIL2 + ' (now with admin)');
    await t.run('overwrite with admin', async function () {
        try {
            await vault2.item(ref).put('test2');
        } catch (e) {
            if (!/primary user session/i.test(e.message || '')) throw e;
            t.info('Re-authorizing ' + t.conf.EMAIL2 + ' to create the app VaultKey…');
            if (vestest.unlockFn) {
                await vestest.unlockFn(t.ves2, t.conf);
            } else {
                await t.ves2.delegate({ domain: t.conf.DOM, email: t.conf.EMAIL2 });
            }
            await vault2.item(ref).put('test2');
        }
    });

    t.head('Retrieving ' + t.conf.OBJ + ' through ' + t.conf.EMAIL);
    await t.run('get via email', async function () { got = await vault1.item(ref).get(); });
    await t.expect('value', 'test2', got);

    t.head('Re-sharing with admin to ' + t.conf.EMAIL + ' from ' + t.conf.EMAIL2);
    await t.run('grant admin back', async function () {
        await vault2.item(ref).share([share1, share2, admin1, admin2]);
    });

    t.head('Deleting ' + t.conf.OBJ);
    await t.run('delete item', async function () {
        await vault1.item(ref).delete();
    });

    t.head('Retrieving ' + t.conf.OBJ + ' — error expected (deleted)');
    await t.run('get deleted rejects', async function () {
        var threw = null;
        try { await vault1.item(ref).get(); } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    t.head('Creating ' + t.conf.OBJ2 + ' through ' + t.conf.EMAIL);
    await t.run('put item2', async function () {
        await vault1.item(ref2).put('test2', [share1]);
    });
    t.head('Deleting ' + t.conf.OBJ2);
    await t.run('delete item2', async function () {
        await vault1.item(ref2).delete();
    });

    t.head('Sharing ' + t.conf.OBJ2 + ' with ' + t.conf.EMAIL2 + ' — error expected (deleted)');
    await t.run('share deleted item rejects', async function () {
        var threw = null;
        try { await vault1.item(ref2).share([share1, share2]); } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    t.head('Creating ' + t.conf.OBJ3 + ' through ' + t.conf.EMAIL);
    await t.run('put item3', async function () {
        await vault1.item(ref3).put('test3', [share1]);
    });
    t.head('Deleting ' + t.conf.OBJ3);
    await t.run('delete item3', async function () {
        await vault1.item(ref3).delete();
    });

    t.info('Section-vault scenarios (read-only sessions, cross-section sharing) ' +
        'and new-user temp-vault auto-creation from the C test are not ported. ' +
        'They depend on keystore-style elevated auth that does not map cleanly ' +
        'onto secondary-vault delegate sessions.');
}, { needsVes2: true });

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['02-share']);
