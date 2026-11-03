/*
 * 08-putvalue.js — libVES.putValue() / getValue(), the item calls on the
 * libVES instance itself (T-0203).
 *
 * putValue(ref, value) without shareWith shares a NEW item with the
 * instance's own vault, and keeps the share list of an existing one. Up to
 * 3.2.2 the new-item default read a global named VES instead of the
 * instance, and rejected with "VES is not defined" unless the page kept its
 * instance in a global by that name; the first step hides any such global.
 *
 * t.ves is the SECONDARY vault //DOM/EMAIL. With t.ves2 (//DOM/EMAIL2) the
 * rewrite step also checks that a second vault stays on the share list.
 *
 * This test writes items, and runs only against an API named explicitly in
 * the vestest conf (apiUrl=..., e.g. the stage API); without one it skips.
 *
 * Runs as `node tests/08-putvalue.js`.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('08-putvalue', async function (t) {
    var obj = t.conf.OBJ + '-pv';
    var ref = libVES.Vault.toRef(obj);
    var own = '//' + t.conf.DOM + '/' + t.conf.EMAIL;

    t.head('putValue / getValue through ' + own);
    if (!t.conf.apiUrl) {
        t.info('skipped: set apiUrl in the vestest conf, this test does not write through the default API');
        return;
    }

    var shareList = async function () {
        var lst = await (await t.ves.getFileItem(ref)).getShareList();
        var rs = await Promise.all(lst.map(async function (sh) {
            if (!(sh instanceof libVES.External)) return 'user:' + await sh.getEmail();
            var f = await sh.getFields({ domain: true, externalId: true });
            return '//' + f.domain + '/' + f.externalId;
        }));
        return rs.sort().join(' ');
    };
    var got, shares;

    t.head('Creating ' + obj + ' with putValue(ref, "test"), no shareWith');
    await t.run('putValue new item', async function () {
        var root = typeof window !== 'undefined' ? window : global;
        var had = 'VES' in root, saved = root.VES;
        if (had) root.VES = undefined;
        try {
            await t.ves.putValue(ref, 'test');
        } finally {
            if (had) root.VES = saved;
        }
    });
    await t.run('getValue', async function () { got = await t.ves.getValue(ref); });
    await t.expect('value is "test"', 'test', got);
    await t.run('share list', async function () { shares = await shareList(); });
    await t.expect('shared with its own vault only', own, shares);

    var all = [own];
    if (t.ves2) {
        all.push('//' + t.conf.DOM + '/' + t.conf.EMAIL2);
        all.sort();
        t.head('Sharing ' + obj + ' with ' + t.conf.EMAIL + ' and ' + t.conf.EMAIL2);
        await t.run('putValue with shareWith', async function () {
            await t.ves.putValue(ref, 'shared', [t.conf.EMAIL, t.conf.EMAIL2].map(function (x) { return { domain: t.conf.DOM, externalId: x }; }));
        });
    }

    t.head('Overwriting ' + obj + ' with putValue(ref, "another test"), no shareWith');
    await t.run('putValue existing item', async function () {
        await t.ves.putValue(ref, 'another test');
    });
    await t.run('getValue', async function () { got = await t.ves.getValue(ref); });
    await t.expect('value is "another test"', 'another test', got);
    if (t.ves2) {
        await t.run('getValue through ' + t.conf.EMAIL2, async function () { got = await t.ves2.getValue(ref); });
        await t.expect('value is "another test"', 'another test', got);
    }
    await t.run('share list', async function () { shares = await shareList(); });
    await t.expect('share list kept', all.join(' '), shares);

    t.head('Deleting ' + obj);
    await t.run('deleteFile', async function () {
        await t.ves.deleteFile(ref);
    });
});

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['08-putvalue']);
