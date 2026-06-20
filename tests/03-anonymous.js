/*
 * 03-anonymous.js — anonymous vaults & anonymous sub-vaults.
 * Mirrors libVES.c/tests/03-anonymous (all 12 steps).
 *
 * Anonymous vaults have an externalId that starts with '!'. They are created
 * via setAnonymousKey on an UNAUTHENTICATED libVES instance — the server
 * requires an anonymous (no-token) session to create an anonymous VaultKey.
 *
 * Anonymous sub-vaults have an externalId of the form `<anon>!<section>`
 * (two '!'-prefixed parts). They are created via setAnonymousKey on a libVES
 * authenticated with the PARENT anon vault's token — the server requires
 * "anonymous parent key authorization" for sub-vault creation.
 *
 * The only deviation from the C test: OBJ's share list adds //.admin/EMAIL
 * so we can clean OBJ up at the end (the C test leaks OBJ; only OBJ2 has
 * admin grant). Functionally identical otherwise.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('03-anonymous', async function (t) {
    var ref = libVES.Vault.toRef(t.conf.OBJ);
    var ref2 = libVES.Vault.toRef(t.conf.OBJ2);
    var subext = t.conf.ANON + t.conf.SEC;            // !vestest-NONCE!vestest-NONCE
    var tempext = t.conf.EMAIL + t.conf.SEC2;         // EMAIL!vestest-NONCE-2
    var emailVault = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL }, t.ves);
    t.conf.ANON_VESKEY = t.conf.ANON_VESKEY || ('anon-' + t.conf.NONCE);
    t.conf.SUB_VESKEY = t.conf.SUB_VESKEY || ('sub-' + t.conf.NONCE);

    // [1] Create anonymous vault — fresh unauthenticated libVES instance.
    t.head('Creating an anonymous vault //' + t.conf.DOM + '/' + t.conf.ANON);
    var anonVes, anonVault;
    await t.run('create anonymous vault', async function () {
        anonVes = new libVES({ domain: t.conf.DOM, externalId: t.conf.ANON, apiUrl: t.ves.apiUrl });
        await anonVes.setAnonymousKey(t.conf.ANON_VESKEY);
        anonVault = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.ANON }, anonVes);
    });

    // [2] Put OBJ via anon, share with EMAIL (+ admin/EMAIL for cleanup at the end).
    t.head('Creating item ' + t.conf.OBJ + ' in the anonymous vault, shared with ' + t.conf.EMAIL);
    await t.run('put item shared anon+email', async function () {
        await anonVault.item(ref).put('test', [
            { domain: t.conf.DOM, externalId: t.conf.ANON },
            { domain: t.conf.DOM, externalId: t.conf.EMAIL },
            { domain: '.admin', externalId: t.conf.EMAIL },
        ]);
    });

    // [3] Read OBJ via anon vault.
    t.head('Retrieving the value of ' + t.conf.OBJ + ' through the anonymous vault');
    var got;
    await t.run('get via anonymous vault', async function () { got = await anonVault.item(ref).get(); });
    await t.expect('value is "test"', 'test', got);

    // [4] Read OBJ via EMAIL.
    t.head('Retrieving the value of ' + t.conf.OBJ + ' through ' + t.conf.EMAIL);
    await t.run('get via email vault', async function () { got = await emailVault.item(ref).get(); });
    await t.expect('value is "test"', 'test', got);

    // [5] Create anonymous sub-vault WITHOUT parent auth — server rejects.
    t.head('Creating anonymous sub-vault without parent auth — error expected');
    await t.run('sub-vault create without parent auth rejects', async function () {
        var noauth = new libVES({ domain: t.conf.DOM, externalId: subext, apiUrl: t.ves.apiUrl });
        var threw = null;
        try { await noauth.setAnonymousKey(t.conf.SUB_VESKEY); } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    // [6] Create anonymous sub-vault WITH parent anon authorization.
    t.head('Creating anonymous sub-vault with parent anon authorization');
    var subVes, subVault;
    await t.run('create anonymous sub-vault', async function () {
        subVes = new libVES({ domain: t.conf.DOM, externalId: subext, apiUrl: t.ves.apiUrl });
        subVes.token = anonVes.token;
        await subVes.setAnonymousKey(t.conf.SUB_VESKEY);
        subVault = new libVES.Vault({ domain: t.conf.DOM, externalId: subext }, subVes);
    });

    // [7] Sub-vault share with non-existing temp vault — server rejects
    //     ("Anonymous vaults are not authorized to create temp keys").
    t.head('Creating item ' + t.conf.OBJ2 + ' via sub-vault with temp-vault share — error expected');
    await t.run('temp-vault share from anon source rejects', async function () {
        var threw = null;
        try {
            await subVault.item(ref2).put('test2', [
                { domain: t.conf.DOM, externalId: t.conf.ANON },
                { domain: t.conf.DOM, externalId: subext },
                { domain: t.conf.DOM, externalId: tempext, user: { email: t.conf.EMAIL } },
            ]);
        } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    // [8] Put OBJ2 via sub-vault, sharing with admin/EMAIL.
    t.head('Creating item ' + t.conf.OBJ2 + ' via sub-vault, shared with admin/' + t.conf.EMAIL);
    await t.run('put item2 shared sub+anon+email+admin', async function () {
        await subVault.item(ref2).put('test2', [
            { domain: t.conf.DOM, externalId: t.conf.ANON },
            { domain: t.conf.DOM, externalId: subext },
            { domain: t.conf.DOM, externalId: t.conf.EMAIL },
            { domain: '.admin', externalId: t.conf.EMAIL },
        ]);
    });

    // [9] Read OBJ2 via parent anon vault.
    t.head('Retrieving the value of ' + t.conf.OBJ2 + ' through the parent anonymous vault');
    await t.run('get item2 via parent anon', async function () { got = await anonVault.item(ref2).get(); });
    await t.expect('value is "test2"', 'test2', got);

    // [10] Read OBJ2 via EMAIL.
    t.head('Retrieving the value of ' + t.conf.OBJ2 + ' through ' + t.conf.EMAIL);
    await t.run('get item2 via email', async function () { got = await emailVault.item(ref2).get(); });
    await t.expect('value is "test2"', 'test2', got);

    // [11] Delete OBJ2 via EMAIL.
    t.head('Deleting ' + t.conf.OBJ2);
    await t.run('delete item2', async function () { await emailVault.item(ref2).delete(); });

    // [12] Get deleted OBJ2 — error expected.
    t.head('Retrieving the deleted ' + t.conf.OBJ2 + ' — error expected');
    await t.run('get item2 after delete rejects', async function () {
        var threw = null;
        try { await emailVault.item(ref2).get(); } catch (e) { threw = e; }
        if (!threw) throw new Error('expected an error');
    });

    // Extra cleanup of OBJ (not in C; OBJ leaks there). Possible thanks to
    // the //.admin/EMAIL grant added in step [2].
    t.head('Deleting ' + t.conf.OBJ + ' (extra cleanup, not in libVES.c test)');
    await t.run('delete item', async function () { await emailVault.item(ref).delete(); });
});

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['03-anonymous']);
