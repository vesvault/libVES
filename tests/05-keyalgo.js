/*
 * 05-keyalgo.js — exercise section vault keys across algorithm families.
 * Mirrors libVES.c/tests/05-keyalgo: RSA, ECDH (one curve), OQS Kyber768 +
 * ML-KEM-{512,768,1024}.
 *
 * Each algo runs the C test's 7 steps:
 *   1. Generate a section vault key under EMAIL
 *   2. -Gp round-trip: getAlgo() returns the expected family
 *   3. Encrypt a Vault Item shared with the section key + EMAIL
 *   4. Decrypt via the section key path (section's encSessionToken)
 *   5. Decrypt via the primary (cross-key) path
 *   6. Export the private key PEM via getUnlockedPrivateKey()
 *   7. Re-import the PEM into a fresh section key, encrypt+decrypt via it
 * Followed by cleanup of both items and both section keys.
 *
 * Option name gotcha (vs an earlier broken version of this file):
 *   libVES.Algo.fromKeyOptions reads namedCurve / modulusLength / oqsAlgo
 *   at the TOP level of optns. There is no `algoOptions` wrapper anywhere
 *   in the lib — passing one silently falls back to the default ECDH P-521.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('05-keyalgo', async function (t) {
    var emailVault = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL }, t.ves);

    var algos = [
        { family: 'RSA',  method: '2048',        optns: { modulusLength: 2048 } },
        { family: 'ECDH', method: 'P-256',       optns: { namedCurve: 'P-256' } },
        { family: 'OQS',  method: 'Kyber768',    optns: { oqsAlgo: 'Kyber768' } },
        { family: 'OQS',  method: 'ML-KEM-512',  optns: { oqsAlgo: 'ML-KEM-512' } },
        { family: 'OQS',  method: 'ML-KEM-768',  optns: { oqsAlgo: 'ML-KEM-768' } },
        { family: 'OQS',  method: 'ML-KEM-1024', optns: { oqsAlgo: 'ML-KEM-1024' } },
    ];

    for (var i = 0; i < algos.length; i++) {
        var a = algos[i];
        var tag = a.family + '-' + a.method;
        var ksec  = t.conf.EMAIL + '!keyalgo-' + tag + '-' + t.conf.NONCE;
        var ksec2 = t.conf.EMAIL + '!keyalgo-' + tag + '-reimp-' + t.conf.NONCE;
        var objk  = '//' + t.conf.DOM + '/keyalgo-' + tag + '-' + t.conf.NONCE;
        var objk2 = '//' + t.conf.DOM + '/keyalgo-' + tag + '-reimp-' + t.conf.NONCE;
        var objRef  = libVES.Vault.toRef(objk);
        var objRef2 = libVES.Vault.toRef(objk2);
        var veskey = 'sec-' + tag + '-' + t.conf.NONCE;
        var ctx = { a: a, tag: tag, ksec: ksec, ksec2: ksec2, objRef: objRef, objRef2: objRef2, veskey: veskey };

        // [1] Generate section key.
        t.head('[' + a.family + ':' + a.method + '] create section vault key');
        await t.run('create section key', async function () {
            await t.ves.setSecondaryKey({ domain: t.conf.DOM, externalId: ctx.ksec }, ctx.veskey, ctx.a.optns);
        });

        // [2] -Gp round-trip: the algo field on the server-side key matches the family.
        t.head('[' + a.family + ':' + a.method + '] getAlgo round-trip');
        await t.run('getAlgo matches family', async function () {
            var k = await t.ves.getSecondaryKey({ domain: t.conf.DOM, externalId: ctx.ksec });
            var algo = await k.getAlgo();
            if (algo !== ctx.a.family) throw new Error('expected algo "' + ctx.a.family + '", got "' + algo + '"');
        });

        // [3] Encrypt a Vault Item shared with the section key + EMAIL.
        t.head('[' + a.family + ':' + a.method + '] encrypt item via section key');
        await t.run('put item shared with section', async function () {
            await emailVault.item(ctx.objRef).put('secret-via-' + ctx.tag + '-' + t.conf.NONCE, [
                { domain: t.conf.DOM, externalId: ctx.ksec },
                { domain: t.conf.DOM, externalId: t.conf.EMAIL },
            ]);
        });

        // [4] Decrypt via the section key path.
        t.head('[' + a.family + ':' + a.method + '] decrypt via section key path');
        var got;
        await t.run('get item via section key', async function () {
            var sectionVault = new libVES.Vault({ domain: t.conf.DOM, externalId: ctx.ksec }, t.ves);
            got = await sectionVault.item(ctx.objRef).get();
        });
        await t.expect('value via section', 'secret-via-' + tag + '-' + t.conf.NONCE, got);

        // [5] Decrypt via the primary (cross-key) path.
        t.head('[' + a.family + ':' + a.method + '] decrypt via primary path');
        await t.run('get item via primary', async function () { got = await emailVault.item(ctx.objRef).get(); });
        await t.expect('value via primary', 'secret-via-' + tag + '-' + t.conf.NONCE, got);

        // [6] Export the private key PEM.
        var pem;
        t.head('[' + a.family + ':' + a.method + '] export private key PEM');
        await t.run('export PEM', async function () {
            var k = await t.ves.getSecondaryKey({ domain: t.conf.DOM, externalId: ctx.ksec });
            pem = await k.getUnlockedPrivateKey();
            if (!/-----BEGIN (PRIVATE|ENCRYPTED PRIVATE) KEY-----/.test(pem)) throw new Error('PEM header missing');
        });

        // [7] Re-import the PEM into a fresh section key + verify encrypt/decrypt.
        t.head('[' + a.family + ':' + a.method + '] re-import PEM, encrypt+decrypt via re-imported key');
        await t.run('re-import PEM into fresh section key', async function () {
            await t.ves.setSecondaryKey({ domain: t.conf.DOM, externalId: ctx.ksec2 }, ctx.veskey, { privateKey: pem });
        });
        await t.run('put item shared with re-imported section', async function () {
            await emailVault.item(ctx.objRef2).put('reimport-' + ctx.tag + '-' + t.conf.NONCE, [
                { domain: t.conf.DOM, externalId: ctx.ksec2 },
                { domain: t.conf.DOM, externalId: t.conf.EMAIL },
            ]);
        });
        await t.run('get item via re-imported section', async function () {
            var reimpVault = new libVES.Vault({ domain: t.conf.DOM, externalId: ctx.ksec2 }, t.ves);
            got = await reimpVault.item(ctx.objRef2).get();
        });
        await t.expect('value via re-import', 'reimport-' + tag + '-' + t.conf.NONCE, got);

        // Cleanup.
        t.head('[' + a.family + ':' + a.method + '] cleanup');
        await t.run('delete item', async function () { await emailVault.item(ctx.objRef).delete(); });
        await t.run('delete reimport item', async function () { await emailVault.item(ctx.objRef2).delete(); });
    }
});

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['05-keyalgo']);
