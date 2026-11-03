/*
 * jstest.inc.js — shared harness for libVES JS tests.
 *
 * A test file registers a single async function via vestest.register(name, fn).
 * The function receives a `t` context with:
 *   t.conf            shared config (DOM, EMAIL, OBJ, ...)
 *   t.ves             authenticated libVES instance (or null for offline tests)
 *   t.report({type, step, info, error})   raw callback
 *   t.head(msg)       section heading
 *   t.run(label, fn)  run fn; pass on resolve, fail on throw
 *   t.expect(label, expected, actual)   strict-equality assertion
 *
 * The same test file is loadable in Node (via require/eval) and in the browser
 * (via <script>). Reporters are pluggable; defaultReporter streams to console
 * with ANSI colors, matching the C suite's vestest.inc.sh output.
 */

(function (root) {
    var vestest = root.vestest = root.vestest || {};
    vestest.registry = vestest.registry || [];

    /*
     * Register a test. `meta` is an optional descriptor used by the runner:
     *   { needsVes2: true }   — test requires a second authorized user.
     */
    vestest.register = function (name, fn, meta) {
        vestest.registry.push({ name: name, run: fn, meta: meta || {} });
    };

    vestest.find = function (name) {
        return vestest.registry.filter(function (e) { return e.name === name; })[0];
    };

    vestest.defaultReporter = function () {
        var pass = 0, fail = 0;
        var ansi = (typeof process !== 'undefined' && process.stdout && process.stdout.isTTY);
        var c = ansi
            ? { head: '\x1b[1;33m', pass: '\x1b[1;32m', fail: '\x1b[1;31m', info: '\x1b[1;30m', stat: '\x1b[1;96m', reset: '\x1b[0m' }
            : { head: '', pass: '', fail: '', info: '', stat: '', reset: '' };
        function log(s) { (typeof process !== 'undefined' ? process.stdout.write(s + '\n') : console.log(s)); }
        function report(ev) {
            switch (ev.type) {
                case 'head':
                    log('');
                    log(c.head + ev.info + c.reset);
                    break;
                case 'pass':
                    pass++;
                    log('[' + c.pass + 'PASSED' + c.reset + '] ' + (ev.step || ''));
                    break;
                case 'fail':
                    fail++;
                    log('[' + c.fail + 'FAILED' + c.reset + '] ' + (ev.step || ''));
                    if (ev.error) log('  ' + (ev.error.stack || ev.error.message || ev.error));
                    break;
                case 'info':
                    log(c.info + (ev.info || '') + c.reset);
                    break;
            }
        }
        report.stats = function () {
            log('');
            log(c.stat + 'Passed: ' + pass + c.reset);
            log(c.stat + 'Failed: ' + fail + c.reset);
        };
        report.counts = function () { return { pass: pass, fail: fail }; };
        return report;
    };

    function ctx(conf, ves, report, ves2) {
        var t = { conf: conf, ves: ves, ves2: ves2 || null, report: report };
        t.needVes2 = function (label) {
            if (t.ves2) return true;
            report({ type: 'fail', step: label || 'requires a second authorized user', error: new Error('no ves2 — set conf.EMAIL2/VESKEY2 (Node) or authorize a second user (browser)') });
            return false;
        };
        t.head = function (msg) { report({ type: 'head', info: msg }); };
        t.info = function (msg) { report({ type: 'info', info: msg }); };
        t.run = function (label, fn) {
            return Promise.resolve().then(fn).then(
                function () { report({ type: 'pass', step: label }); },
                function (e) { report({ type: 'fail', step: label, error: e }); }
            );
        };
        t.expect = function (label, expected, actual) {
            return t.run(label, function () {
                if (expected !== actual) throw new Error('expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
            });
        };
        return t;
    }

    /*
     * Run one named test against a prepared ves instance + config.
     * Returns a promise resolving when the test finishes (pass or fail).
     * Optional `ves2` is exposed on the test as t.ves2 for multi-user tests.
     */
    vestest.runOne = function (name, conf, ves, report, ves2) {
        report = report || vestest.defaultReporter();
        var entry = vestest.registry.filter(function (e) { return e.name === name; })[0];
        if (!entry) return Promise.reject(new Error('no test: ' + name));
        return Promise.resolve().then(function () { return entry.run(ctx(conf, ves, report, ves2)); });
    };

    /*
     * Run every registered test sequentially against the same ves instance.
     * If `report` is not provided, the default reporter is used and stats are
     * printed when everything finishes. Optional `ves2` is forwarded to each
     * test as t.ves2.
     */
    vestest.runAll = function (conf, ves, report, ves2) {
        return vestest.runSelected(null, conf, ves, report, ves2);
    };

    /*
     * Run a subset of registered tests. `names` is an array of test names,
     * or null/undefined to run all.
     */
    vestest.runSelected = function (names, conf, ves, report, ves2) {
        var owned = !report;
        report = report || vestest.defaultReporter();
        var entries = names
            ? names.map(function (n) { return vestest.find(n); }).filter(function (e) { return e; })
            : vestest.registry;
        var p = Promise.resolve();
        entries.forEach(function (entry) {
            p = p.then(function () { return entry.run(ctx(conf, ves, report, ves2)); });
        });
        return p.then(function () {
            if (owned && report.stats) report.stats();
            return report.counts ? report.counts() : null;
        });
    };

    /*
     * The tests unlock vaults and write and delete items, so they talk only
     * to servers the conf names. libVES defaults apiUrl, pollUrl and wwwUrl
     * (VESlocker, the /api/msg key sync, the VESvault popup) to PRODUCTION:
     * https://api.ves.host/v1/, https://poll.ves.host/v1/,
     * https://www.vesvault.com/. So:
     *   - apiUrl is required;
     *   - apiUrl set to the production API (the libVES default) is the
     *     opt-in to production, and pollUrl and wwwUrl may then default;
     *   - with any other apiUrl, pollUrl and wwwUrl are required too, so a
     *     run against another server never falls back to production.
     * Throws if the conf falls short. The runners call it before they build
     * any libVES instance, so a refused run makes no network request.
     */
    vestest.checkConf = function (conf) {
        var dflt = root.libVES.prototype;
        if (!conf.apiUrl) throw new Error('vestest: apiUrl is not set. Without it libVES uses its default, '
            + dflt.apiUrl + ', the PRODUCTION API. Set apiUrl, pollUrl and wwwUrl to the servers to test against, '
            + 'or set apiUrl=' + dflt.apiUrl + ' to run against production on purpose.');
        ['pollUrl', 'wwwUrl'].forEach(function (k) {
            if (!conf[k] && conf.apiUrl !== dflt.apiUrl) throw new Error('vestest: apiUrl is ' + conf.apiUrl
                + ' but ' + k + ' is not set, and would default to ' + dflt[k] + ', which is PRODUCTION. Set ' + k + ' too.');
        });
        return conf;
    };

    /*
     * libVES options for a test instance built from the conf: `optns` plus
     * the conf's apiUrl, pollUrl and wwwUrl, after vestest.checkConf.
     */
    vestest.libVESoptns = function (conf, optns) {
        vestest.checkConf(conf);
        ['apiUrl', 'pollUrl', 'wwwUrl'].forEach(function (k) { if (conf[k]) optns[k] = conf[k]; });
        return optns;
    };

    /*
     * Build an authenticated libVES instance from a flat conf record.
     * External apps use a SECONDARY vault — identified by domain + externalId.
     * (Primary `{user: email}` vaults route through VESvault.com's extra
     * security and are not the right shape for an external app integration
     * test.)
     *
     * Unlock is performed via vestest.unlockFn, which the runtime must
     * register before calling openVES. tests/node.inc.js wires it to a
     * libVES.KeyStore (CLI PIN dialog, file-backed key cache); browser
     * callers wire their own (e.g. ves.delegate()-based) flow.
     */
    vestest.openVES = function (conf) {
        var optns = vestest.libVESoptns(conf, { domain: conf.DOM, externalId: conf.EMAIL });
        var ves = new root.libVES(optns);
        if (!vestest.unlockFn) return Promise.reject(new Error('vestest.unlockFn not set — runtime must register an unlock implementation'));
        return Promise.resolve(vestest.unlockFn(ves, conf)).then(function () { return ves; });
    };

    /*
     * Like openVES but for the second user (conf.EMAIL2). Returns null if
     * EMAIL2 is not set.
     */
    vestest.openVES2 = function (conf) {
        if (!conf.EMAIL2) return Promise.resolve(null);
        var optns = vestest.libVESoptns(conf, { domain: conf.DOM, externalId: conf.EMAIL2 });
        var ves = new root.libVES(optns);
        if (!vestest.unlockFn) return Promise.reject(new Error('vestest.unlockFn not set — runtime must register an unlock implementation'));
        return Promise.resolve(vestest.unlockFn(ves, conf)).then(function () { return ves; });
    };

    /*
     * Generate a per-run nonce so item refs do not collide across runs,
     * mirroring NONCE=`date +%y%m%d%H%M%S`.$$ in vestest.conf.
     */
    vestest.nonce = function () {
        var d = new Date();
        function p(n, w) { n = String(n); while (n.length < w) n = '0' + n; return n; }
        return p(d.getFullYear() % 100, 2) + p(d.getMonth() + 1, 2) + p(d.getDate(), 2)
            + p(d.getHours(), 2) + p(d.getMinutes(), 2) + p(d.getSeconds(), 2)
            + '.' + Math.floor(Math.random() * 1e6);
    };

    /*
     * Fill in OBJ/OBJ2/... based on NONCE+DOM the same way vestest.conf does,
     * so test files can reference t.conf.OBJ without restating the formula.
     */
    vestest.fillConf = function (conf) {
        conf.NONCE = conf.NONCE || vestest.nonce();
        conf.DOM = conf.DOM || 'demo';
        // DOM2: in a browser, default to a fresh experimental name per run
        // (mirrors libVES.c's `DOM2="x-vestest-$NONCE"`). The browser path
        // can bootstrap the domain via libVES.subtle(...).unlock() — VES.unlock
        // fails on the fresh ves, the catch falls through to delegate, and
        // the VESvault popup performs the primary,elevate,save that
        // auto-creates the experimental domain server-side. In Node we leave
        // DOM2 unset: keystore-only unlock can't run that bootstrap, so the
        // test self-skips with a hint to pre-create the domain via the C CLI.
        if (typeof document !== 'undefined') conf.DOM2 = conf.DOM2 || ('x-vestest-' + conf.NONCE);
        conf.OBJ = conf.OBJ || ('//' + conf.DOM + '/vestest-' + conf.NONCE);
        conf.OBJ2 = conf.OBJ2 || (conf.OBJ + '-2');
        conf.OBJ3 = conf.OBJ3 || (conf.OBJ + '-3');
        // SEC = anonymous-style section marker ('!' = '%21' URL-encoded);
        // ANON = standalone anonymous vault externalId (also '!'-prefixed).
        conf.SEC = conf.SEC || ('!vestest-' + conf.NONCE);
        conf.ANON = conf.ANON || ('!vestest-' + conf.NONCE);
        conf.SEC2 = conf.SEC2 || ('!vestest-' + conf.NONCE + '-2');
        return conf;
    };
})(typeof window !== 'undefined' ? window : global);
