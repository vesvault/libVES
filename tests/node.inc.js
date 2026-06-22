/*
 * tests/node.inc.js — Node-side bootstrap for the libVES JS test suite.
 *
 * Each test file (01-item.js, …) requires this at the top to load the
 * self-contained node package (libVES.node.js — the OQS + ECDH wasm engines
 * are base64-embedded, no sidecar .wasm, no document), wire libVES.KeyStore
 * to the libVES.c-compatible keydir (so the `ves` CLI and these tests share
 * key storage), and register vestest.unlockFn. The top-line require is
 * guarded with `typeof window === 'undefined'`, so the same test files
 * load unchanged into tests/index.html in the browser.
 *
 * Standalone usage:
 *     node tests/01-item.js                    # one test
 *     node tests/node.inc.js                   # all tests in this dir
 *     node tests/node.inc.js 01-item 03-anon   # named subset
 *
 * Config:  shell-style ~/.vestest.conf (same format as
 *          libVES.c/tests/vestest.conf):
 *      EMAIL=user@domain.com
 *      EMAIL2=user2@domain.com         # optional, for 02-share / 04-domain
 *      DOM=demo                        # optional, defaults to 'demo'
 *      DOM2=...                        # optional, for 04-domain
 *      apiUrl=https://api.ves.host/v1/ # optional
 *
 *   Set VESTEST_CONF to point at a different file. A legacy JS conf
 *   (module.exports = {...}) at $VESTEST_CONF, tests/vestest.conf.js, or
 *   ~/.vestest.conf.js is still honored if the shell conf is absent.
 *
 * Keys:    No VESkeys live in the conf. Keys come from the libVES.c-style
 *          keydir at $VES_KEYSTORE (or ~/.ves/), so the `ves` CLI and this
 *          test runner share storage — files like
 *          <domain>^<extid>.{key,ses,lkr}. .key/.ses entries are read
 *          directly; .lkr (PIN-encrypted) entries trigger a terminal PIN
 *          prompt with echo disabled. On a fresh keydir, libVES.KeyStore
 *          falls back to the cross-device /api/msg sync.
 *
 * Node 19+ exposes WebCrypto natively; older Node needs `npm i subtle`.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

if (typeof crypto === 'undefined') {
    global.crypto = require('crypto');
    global.crypto.subtle = (global.crypto.webcrypto && global.crypto.webcrypto.subtle) || require('subtle');
}

const LIB_DIR = path.resolve(__dirname, '..');

// Load the SHIPPED node package alone — libVES.node.js is the self-contained npm
// bundle (package.json "main") with the OQS + ECDH wasm engines base64-embedded
// (single-file). This is exactly what `require('libves')` gives an npm consumer:
// no individual source files, no sidecar .wasm fetch, no document. Exercising the
// bundle here also proves it works standalone. Build it first on the build host:
// `node build.js` (needs the emscripten glue — see WasmOQS/ and WasmECDH/).
const PKG = path.join(LIB_DIR, 'libVES.node.js');
if (!fs.existsSync(PKG)) throw new Error('missing ' + PKG
    + ' — build the node package first: (cd ' + LIB_DIR + ' && node build.js).');
global.libVES = require(PKG);

eval.call(global, fs.readFileSync(path.join(__dirname, 'jstest.inc.js'), 'utf8'));

// ---------------------------------------------------------------------------
// Shell-conf parser (libVES.c/tests/vestest.conf format).
// Only literal KEY=value lines are read; shell-dynamic values ($VAR, `cmd`,
// $(cmd)) are skipped — NONCE / OBJ / SEC etc. are recomputed by
// vestest.fillConf().
// ---------------------------------------------------------------------------
function parseShellConf(text) {
    const conf = {};
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.replace(/^\s*#.*$/, '');
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
        if (!m) continue;
        let [, k, v] = m;
        if (/[`$\\]/.test(v)) continue;
        v = v.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
        if (/%[0-9a-f]{2}/i.test(v)) {
            try { v = decodeURIComponent(v); } catch {}
        }
        conf[k] = v;
    }
    return conf;
}

function loadConf() {
    const candidates = [
        process.env.VESTEST_CONF,
        path.join(os.homedir(), '.vestest.conf'),
        path.join(__dirname, 'vestest.conf.js'),
        path.join(os.homedir(), '.vestest.conf.js'),
    ].filter(Boolean);
    for (const p of candidates) {
        if (!fs.existsSync(p)) continue;
        if (p.endsWith('.js')) return require(p);
        return parseShellConf(fs.readFileSync(p, 'utf8'));
    }
    throw new Error('No vestest config found. Create ~/.vestest.conf (libVES.c shell style) or set VESTEST_CONF.');
}

// ---------------------------------------------------------------------------
// Keydir-style file store, byte-compatible with libVES.c/lib/KeyStore/keydir.c.
//
// Layout:    <root>/<domain>^<extid><suffix>
//   suffix:  .ses (session token, plaintext)
//            .key (veskey, plaintext)
//            .lkr (PIN-encrypted VESlocker entry)
//   - bad chars in domain/extid are replaced with '.' (matches keydir.c)
//   - no domain → filename is just <extid><suffix>
//
// Plugs into libVES.KeyStore via {store: makeKeydirStore(...)}, which
// satisfies the get(domain,extid,flags)/put/delete contract directly and
// bypasses the default localStorage backend entirely.
// ---------------------------------------------------------------------------
function makeKeydirStore(rootDir) {
    // Char set from libVES.c/lib/KeyStore/keydir.c:libVES_KeyStore_keydir_badchrs
    const BAD = /[\x00-\x1f"'`:;,\[\](){}<>|^/\\*?\x7f]/g;
    const safe = (s) => s == null ? '' : String(s).replace(BAD, '.');
    const suffix = (f) => f.sess ? '.ses' : f.nopin ? '.key' : '.lkr';
    const fpath = (domain, extid, flags) =>
        path.join(rootDir, (domain ? safe(domain) + '^' : '') + safe(extid) + suffix(flags));

    return {
        async get(domain, extid, flags) {
            try { return fs.readFileSync(fpath(domain, extid, flags), 'utf8'); }
            catch (e) { return null; }
        },
        async put(domain, extid, value, flags) {
            fs.mkdirSync(rootDir, { recursive: true, mode: 0o700 });
            fs.writeFileSync(fpath(domain, extid, flags), String(value), { mode: 0o600 });
            return true;
        },
        async delete(domain, extid, flags) {
            try { fs.unlinkSync(fpath(domain, extid, flags)); } catch (e) {}
            return true;
        },
    };
}

// Minimal in-memory localStorage shim so VESlocker.js (if ever loaded
// alongside) doesn't crash on missing global. libVES.KeyStore uses the
// keydir store above and never touches localStorage.
function makeMemoryLocalStorage() {
    const data = {};
    const methods = {
        get length() { return Object.keys(data).length; },
        key(i)        { return Object.keys(data)[i] ?? null; },
        getItem(n)    { return data[n] ?? null; },
        setItem(n,v)  { data[n] = String(v); },
        removeItem(n) { delete data[n]; },
        clear()       { for (const k in data) delete data[k]; },
    };
    const own = (k) => Object.prototype.hasOwnProperty.call(methods, k);
    return new Proxy(methods, {
        get(t, k)       { return own(k) ? t[k] : data[k]; },
        set(t, k, v)    { if (own(k)) t[k] = v; else data[k] = String(v); return true; },
        deleteProperty(_, k) { delete data[k]; return true; },
        has(_, k)       { return k in data || own(k); },
        ownKeys()       { return Object.keys(data); },
        getOwnPropertyDescriptor(_, k) {
            if (k in data) return { configurable: true, enumerable: true, value: data[k], writable: true };
        },
    });
}

// ---------------------------------------------------------------------------
// CLI dialog — raw-stdin PIN entry, sync-code display, status messages.
// Mirrors libVES.c/lib/KeyStore/cli/KeyStore_cli.c.
// ---------------------------------------------------------------------------
const writeErr = (s) => process.stderr.write(s);

function readPin(prompt) {
    return new Promise((resolve, reject) => {
        const stdin = process.stdin;
        if (!stdin.isTTY) return reject(new Error('PIN entry needs a TTY — re-run with `ssh -t build` or similar'));
        writeErr(prompt);
        const wasRaw = stdin.isRaw;
        stdin.setRawMode(true);
        stdin.resume();
        let buf = '';
        const onData = (chunk) => {
            for (const c of chunk.toString('utf8')) {
                if (c === '\r' || c === '\n') {
                    stdin.removeListener('data', onData);
                    stdin.setRawMode(wasRaw);
                    stdin.pause();
                    writeErr('\n');
                    return resolve(buf);
                }
                if (c === '\x03') { writeErr('\n'); process.exit(130); }
                if (c === '\x7f' || c === '\b') { buf = buf.slice(0, -1); continue; }
                if (c >= ' ' && c.charCodeAt(0) < 0x80) buf += c;
            }
        };
        stdin.on('data', onData);
    });
}

async function cliPrompt(ctx) {
    const ansi = process.stderr.isTTY;
    const c = ansi
        ? { hdr: '\x1b[1;33m', warn: '\x1b[1;31m', ok: '\x1b[1;32m', reset: '\x1b[0m' }
        : { hdr: '', warn: '', ok: '', reset: '' };
    const id = ctx.domain ? (ctx.domain + '/' + (ctx.extid ?? '')) : (ctx.email ?? '?');

    switch (ctx.state) {
        case 'sync': {
            const url = (ctx.ves?.wwwUrl ?? 'https://www.vesvault.com/') + 'vv/exportkey';
            writeErr('\n' + c.hdr + 'VESvault sync for ' + id + c.reset + '\n');
            writeErr('Open ' + url + ' on another device and enter: ' + c.hdr + ctx.syncode + c.reset + '\n\n');
            return {};
        }
        case 'pinretry':
            writeErr(c.warn + 'Incorrect PIN' + (ctx.retry ? ' (wait ' + ctx.retry + 's)' : '') + c.reset + '\n');
            if (ctx.retry) await new Promise((r) => setTimeout(r, ctx.retry * 1000));
            // fall through
        case 'pin':
            return { pin: await readPin(c.hdr + 'PIN for ' + id + c.reset + ': ') };
        case 'close':
        case 'done':
            writeErr(c.ok + 'Unlocked ' + id + c.reset + '\n');
            return {};
        case 'nouser':
            writeErr(c.warn + 'User ' + id + ' is not registered with VES' + c.reset + '\n');
            return {};
        default:
            return {};
    }
}

// ---------------------------------------------------------------------------
// Wire KeyStore-based unlock into the harness.
//
// Storage is the libVES.c-compatible keydir at $VES_KEYSTORE (or ~/.ves/),
// so keys populated by the `ves` CLI are picked up automatically.
// ---------------------------------------------------------------------------
const keydirRoot = process.env.VES_KEYSTORE || path.join(os.homedir(), '.ves');
global.localStorage = makeMemoryLocalStorage();

const keystore = new libVES.KeyStore({
    prompt: cliPrompt,
    store: makeKeydirStore(keydirRoot),
});
vestest.unlockFn = (ves) => keystore.unlock(ves);

/*
 * vestest.runFromNode([names]) — entry point for `node 0X-...js` and for the
 * run-all driver below. Reads conf, opens ves (and ves2 if EMAIL2 is set),
 * runs the named tests (default: every test currently in the registry), and
 * exits with status 0/1/2.
 */
vestest.runFromNode = function (names) {
    return (async () => {
        const conf = vestest.fillConf(loadConf());
        if (!conf.EMAIL) throw new Error('EMAIL is required in vestest conf');
        const ves = await vestest.openVES(conf);
        const ves2 = await vestest.openVES2(conf);
        const report = vestest.defaultReporter();
        const counts = await vestest.runSelected(names || null, conf, ves, report, ves2);
        report.stats();
        process.exit(counts.fail ? 1 : 0);
    })().catch((e) => { console.error(e); process.exit(2); });
};

// When this file is the entry point, discover and load every numbered test
// file in this directory, then run them all (or a subset given on argv).
if (require.main === module) {
    const args = process.argv.slice(2);
    const testFiles = args.length
        ? args.map(a => a.endsWith('.js') ? a : a + '.js')
        : fs.readdirSync(__dirname).filter(f => /^\d.*\.js$/.test(f)).sort();
    for (const f of testFiles) require(path.join(__dirname, f));
    vestest.runFromNode(args.length ? args.map(a => a.replace(/\.js$/, '')) : null);
}
