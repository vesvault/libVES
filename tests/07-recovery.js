/*
 * 07-recovery.js — a recovery friend refuses the role.
 *
 * EMAIL names EMAIL2 as its only recovery friend (setShadow), EMAIL2 finds
 * the recovery among its friends' recoveries and refuses it, and EMAIL's
 * recovery no longer counts EMAIL2.
 *
 * Unlike the other tests this one uses PRIMARY vaults ({user: email}):
 * recovery is a primary-vault feature. Node only (the key store unlocks the
 * primary vaults; tests/index.html has no way to), so it is not listed there.
 * It changes EMAIL's recovery setup, so it skips if EMAIL already has one,
 * and removes the one it creates.
 *
 * The primary vaults unlock from the keydir's .lkr entries with the PIN,
 * which needs VESlocker (https://github.com/vesvault/VESlocker):
 *     VESLOCKER_JS=.../VESlocker/client/VESlocker.js node tests/node.inc.js 07-recovery
 * Set wwwUrl in the conf to the site the .lkr entries were made on. VESlocker
 * rewrites an .lkr on every unlock, as the `ves` CLI does.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('07-recovery', async function (t) {
    if (!t.needVes2('07-recovery requires a second authorized user')) return;

    function primary(email) {
        var optns = { user: email };
        if (t.conf.apiUrl) optns.apiUrl = t.conf.apiUrl;
        if (t.conf.pollUrl) optns.pollUrl = t.conf.pollUrl;
        if (t.conf.wwwUrl) optns.wwwUrl = t.conf.wwwUrl;
        var ves = new libVES(optns);
        return Promise.resolve(vestest.unlockFn(ves, t.conf)).then(function () { return ves; });
    }
    async function friendsTotal(ves) {
        var shadow = await ves.getShadowKey();
        delete shadow.vaultItems;
        var rcv = await shadow.getRecovery();
        return rcv.getFriendsTotal();
    }
    async function ownersRecovery(friend, owner) {
        var me = await friend.me();
        delete me.friendsKeyItems;
        var ownerId = await (await owner.me()).getId();
        var rcvs = await friend.getFriendsRecoveries();
        for (var i = 0; i < rcvs.length; i++) {
            if (await (await rcvs[i].vaultKey.getUser()).getId() == ownerId) return rcvs[i];
        }
        return null;
    }

    var owner, friend, rcv, total;

    t.head('Unlocking the primary vaults of ' + t.conf.EMAIL + ' and ' + t.conf.EMAIL2);
    await t.run('unlock ' + t.conf.EMAIL, async function () { owner = await primary(t.conf.EMAIL); });
    await t.run('unlock ' + t.conf.EMAIL2, async function () { friend = await primary(t.conf.EMAIL2); });
    if (!owner || !friend) return;

    if (await owner.getShadowKey()) {
        t.info(t.conf.EMAIL + ' already has a recovery setup; not replacing it, skipped');
        return;
    }

    t.head(t.conf.EMAIL + ' names ' + t.conf.EMAIL2 + ' as its only recovery friend');
    await t.run('setShadow', async function () { await owner.setShadow([t.conf.EMAIL2], { n: 1 }); });
    try {
        await t.run('count friends', async function () { total = await friendsTotal(owner); });
        await t.expect('the owner counts one friend', 1, total);

        t.head(t.conf.EMAIL2 + ' refuses');
        await t.run('find the recovery', async function () {
            rcv = await ownersRecovery(friend, owner);
            if (!rcv) throw new Error('not among the friend\'s recoveries');
        });
        await t.run('refuse', async function () { await rcv.refuse(); });

        await t.run('count friends', async function () { total = await friendsTotal(owner); });
        await t.expect('the owner counts no friend', 0, total);
        await t.run('the friend no longer has the recovery', async function () {
            var r = await ownersRecovery(friend, owner);
            if (r && await r.getMyToken().catch(function () { return null; })) throw new Error('the friend still holds a token');
        });
        await t.run('refusing again fails', async function () {
            var threw = null;
            try { await rcv.refuse(); } catch (e) { threw = e; }
            if (!threw) throw new Error('expected an error');
        });
    } finally {
        t.head('Removing the recovery setup');
        await t.run('setShadow([])', async function () { await owner.setShadow([]); });
    }
});
