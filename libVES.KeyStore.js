/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * libVES.KeyStore.js   Local key storage with PIN-encrypted entries and
 *                      cross-device sync. JS counterpart to
 *                      libVES.c/lib/libVES/KeyStore.{c,h}.
 *
 * VESlocker (https://github.com/vesvault/VESlocker) is loaded separately,
 * via <script src="VESlocker.js"> in the browser or by attaching to the
 * global before this file runs in Node. If a method needs VESlocker and it
 * is not present, the call rejects with libVES.Error.Internal.
 *
 * Flags are word-form. Pass any of:
 *   - dict   {nopin: true, save: true}
 *   - array  ['nopin', 'save']
 *   - string 'nopin,save'   (comma-separated; whitespace ignored)
 *   - string 'nopin'        (single flag)
 * Recognized words mirror LIBVES_KS_*: nopin, nosync, save, persist, sess,
 * resync, forget, primary, elevate.
 *
 * API endpoint paths are relative to the dialog's ves.wwwUrl; absolute
 * URLs in api overrides pass through unchanged. KeyStore methods that
 * touch network always run through a dialog and source wwwUrl from the
 * ves instance carried by that dialog.
 *
 ***************************************************************************/


libVES.KeyStore = class {
    constructor(optns) {
        optns ||= {};
        this.prompt = optns.prompt;
        this.api = {...libVES.KeyStore.apiDefault, ...optns.api};
        this.store = optns.store;
        this._locker = optns.locker;
        this._localStorage = optns.localStorage ?? (typeof localStorage !== 'undefined' ? localStorage : null);
    }

    _apiUrl(ves, key) {
        let p = this.api[key];
        if (p == null) throw new libVES.Error.Internal('Unknown KeyStore API endpoint: ' + key);
        if (/^[a-z]+:\/\//i.test(p)) return p;
        let base = ves?.wwwUrl;
        if (!base) throw new libVES.Error.Internal('libVES.KeyStore: ves with wwwUrl is required for relative API paths');
        return base + p;
    }

    getLocker(ves) {
        if (this._locker) return this._locker;
        if (typeof VESlocker === 'undefined') {
            throw new libVES.Error.Internal('VESlocker not loaded — include https://github.com/vesvault/VESlocker before using libVES.KeyStore');
        }
        return (this._locker = new VESlocker({apiUrl: this._apiUrl(ves, 'locker')}));
    }

    _ls() {
        if (!this._localStorage) throw new libVES.Error.Internal('No localStorage available — pass {localStorage: ...} to libVES.KeyStore for non-browser use');
        return this._localStorage;
    }

    _key(domain, extid, flags) {
        const kind = flags.sess ? 'SessId' : flags.nopin ? 'VESkey_t' : 'VESkey';
        return `${kind}:${domain ?? ''}/${extid ?? ''}`;
    }

    async get(domain, extid, flags) {
        flags = libVES.KeyStore.flags(flags);
        if (this.store) return this.store.get(domain, extid, flags);
        if (!(flags.sess || flags.nopin)) {
            throw new libVES.Error.Internal('PIN-encrypted get is handled inside unlock(); raw get() not supported for that path');
        }
        return this._ls()[this._key(domain, extid, flags)] ?? null;
    }

    async put(domain, extid, value, flags) {
        flags = libVES.KeyStore.flags(flags);
        if (this.store) return this.store.put(domain, extid, value, flags);
        if (!(flags.sess || flags.nopin)) {
            throw new libVES.Error.Internal('PIN-encrypted put is handled inside unlock(); raw put() not supported for that path');
        }
        this._ls()[this._key(domain, extid, flags)] = value;
        return true;
    }

    async delete(domain, extid, flags) {
        flags = libVES.KeyStore.flags(flags);
        if (this.store) return this.store.delete(domain, extid, flags);
        delete(this._ls()[this._key(domain, extid, flags)]);
        return true;
    }

    async _dialog(ctx) {
        if (!this.prompt) throw new libVES.Error('Dialog', 'No prompt callback configured on libVES.KeyStore');
        const rsp = (await this.prompt(ctx)) || {};
        if (ctx.state === 'pin' && rsp.pin == null) throw new libVES.Error('Dialog', 'Cancelled');
        return rsp;
    }

    async savekey(ref, key) {
        if (!ref?.domain || key == null) return false;
        await this.put(ref.domain, ref.externalId, String(key), {save: true, nopin: true});
        return true;
    }

    /***********************************************************************
     * forget(ves, flags) — remove all locally cached entries for the
     * identity carried by `ves`. Unlike the C keydir which colocates all
     * flag variants under one file path, this JS backend namespaces by
     * flag, so forget() walks every variant explicitly (sess, nopin, and
     * the PIN-encrypted default kind) for each location.
     ***********************************************************************/
    async forget(ves, flags) {
        flags = libVES.KeyStore.flags(flags);
        const ext = ves.external ?? (ves.domain ? {domain: ves.domain, externalId: ves.externalId} : null);
        const locations = [
            ext?.domain ? [ext.domain, ext.externalId] : null,
            (!flags.sess && ves.user) ? [null, ves.user] : null,
        ].filter(Boolean);
        const kinds = [{sess: true}, {nopin: true}, {}];
        for (const [d, e] of locations) {
            for (const k of kinds) await this.delete(d, e, k);
        }
        return ves;
    }

    /***********************************************************************
     * unlock(ves, flags) — port of libVES_KeyStore_unlock from libVES.c.
     * Tries cached entries first, then falls back to PIN-decrypt of a
     * locally-cached encrypted veskey, then to /api/msg cross-device sync.
     *
     * flags is dict/array/string with words from: nopin, nosync, save,
     *       persist, sess, resync, forget, primary, elevate
     ***********************************************************************/
    async unlock(ves, flags) {
        flags = libVES.KeyStore.flags(flags);
        if (flags.forget) return this.forget(ves, flags);

        const ext = ves.external ?? (ves.domain ? {domain: ves.domain, externalId: ves.externalId} : null);
        const email = ves.user;
        if (!ext && !email) throw new libVES.Error.InvalidValue('libVES.KeyStore.unlock: ves has neither external ref nor user email');

        const dlg = {
            state: 'init',
            flags,
            ves,
            ks: this,
            api: this.api,
            domain: ext?.domain ?? null,
            extid: ext?.externalId ?? null,
            email,
        };

        const swallow = async (p) => { try { return await p; } catch { return null; } };

        // 1. Cached session token under (domain, extid)
        if (dlg.domain && flags.sess && !flags.resync && !flags.primary) {
            const sess = await swallow(this.get(dlg.domain, dlg.extid, {...flags, nopin: true}));
            if (sess) { ves.token = sess; return ves; }
        }

        // 2. Cached plaintext (nopin) veskey under (domain, extid)
        if (dlg.domain && !flags.sess && !flags.save && !flags.resync && !flags.primary) {
            const veskey = await swallow(this.get(dlg.domain, dlg.extid, {...flags, sess: false, nopin: true}));
            if (veskey && await swallow(ves.unlock(veskey).then(() => true))) return ves;
        }

        // 3. Cached email-keyed entry + PIN-decrypt via VESlocker
        if (!flags.resync && email) {
            const sess = await swallow(this.get(null, email, {...flags, sess: true, nopin: true}));
            if (sess) {
                if (flags.nopin) {
                    const veskey = await swallow(this.get(null, email, {...flags, sess: false, nopin: true}));
                    if (veskey) {
                        ves.token = sess;
                        if (await swallow(ves.unlock(veskey).then(() => true))) return ves;
                    }
                } else {
                    const locker = this.getLocker(ves);
                    const name = 'VESkey' + this._lockerName(null, email);
                    if (locker.exists(name)) {
                        const veskey = await this._pinLoop(dlg, (pin) => locker.fetch(name, pin));
                        if (veskey) {
                            ves.token = sess;
                            if (await swallow(ves.unlock(veskey).then(() => true))) return ves;
                        }
                    }
                }
            }
        }

        // 4. Fall back to cross-device /api/msg sync
        if (flags.nosync) throw new libVES.Error('NotFound', 'Key not found in the KeyStore and sync is disabled (nosync)');
        return this._dialogImport(dlg);
    }

    /***********************************************************************
     * Cross-device sync. Mirrors libVES_KeyStore_dialog_import in
     * libVES.c. Adapted from ves-www/import.html.php which is the
     * receiving-side counterpart already shipped on www.vesvault.com.
     ***********************************************************************/
    async _dialogImport(dlg) {
        const ves = dlg.ves;
        const cur = ves.me ? await (await ves.me()).getCurrentVaultKey() : await ves.getVaultKey();
        const keyId = await cur.getId();

        const ekey = new libVES.VaultKey({type: 'temp', algo: ves.keyAlgo ?? 'ECDH'}, ves);
        const pub = await ekey.getPublicKey();
        const msg = await this._postForm(this._apiUrl(ves, 'msg'), {vaultKeyId: keyId, publicKey: pub});
        const code = msg?.code;
        if (!code) throw new libVES.Error('Dialog', 'No sync code received from /api/msg');

        dlg.state = 'sync';
        dlg.syncode = code;
        await this._dialog(dlg);

        const encData = await this._pollMsg(ves, keyId, code);
        let sync = await ekey.decrypt(encData);
        if (sync instanceof Uint8Array || sync instanceof ArrayBuffer) {
            sync = libVES.Util.ByteArrayToString?.(sync) ?? new TextDecoder().decode(sync);
        }
        sync = String(sync);

        const locker = this.getLocker(ves);
        const decrypt = locker.decryptEntry?.bind(locker) ?? locker.decrypt.bind(locker);
        const veskey = await this._pinLoop(dlg, (pin) => decrypt(pin, sync));
        if (!veskey) throw new libVES.Error('Dialog', 'PIN dialog failed');

        await ves.unlock(veskey);
        dlg.state = 'close';
        await this._dialog(dlg);
        return ves;
    }

    /***********************************************************************
     * PIN entry loop. fetchfn(pin) resolves to a veskey on success or
     * rejects; retries on bad-PIN errors (VESlocker codes VL/-11/-12) and
     * surfaces anything else.
     ***********************************************************************/
    async _pinLoop(dlg, fetchfn) {
        for (let retry = 0; ; retry++) {
            dlg.state = retry ? 'pinretry' : 'pin';
            dlg.retry = retry;
            const {pin} = await this._dialog(dlg);
            if (!pin) return null;
            try {
                return await fetchfn(pin);
            } catch (e) {
                const code = e?.code ?? e?.error;
                if (code === 'VL' || code === -12 || code === -11) continue;
                throw e;
            }
        }
    }

    _lockerName(domain, extid) {
        return `${domain ?? ''}/${extid ?? ''}`;
    }

    async _postForm(url, params) {
        const body = new URLSearchParams(params).toString();
        const res = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
            body,
        });
        if (res.status === 304) return null;
        if (!res.ok) throw new libVES.Error('HttpError', `${url}: ${res.status} ${res.statusText}`);
        return res.json();
    }

    async _pollMsg(ves, keyId, code, deadline) {
        deadline ??= Date.now() + 5 * 60 * 1000;
        const url = this._apiUrl(ves, 'msg');
        while (true) {
            const msg = await this._postForm(url, {vaultKeyId: keyId, code});
            if (msg?.encData) return msg.encData;
            if (Date.now() > deadline) throw new libVES.Error('Timeout', '/api/msg sync timed out');
            await new Promise((r) => setTimeout(r, 1000));
        }
    }
};


// API endpoint paths, relative to ves.wwwUrl (mirror libVES_KeyStore_api_default).
// Absolute URLs in `api` overrides are passed through unchanged.
libVES.KeyStore.apiDefault = {
    locker:     'api/VESlocker',
    msg:        'api/msg',
    exportkey:  'vv/exportkey',
    importdone: 'vv/import_done/',
};

/***************************************************************************
 * Normalize a flags argument into a dict of truthy lowercase words.
 *   undefined/null      →  {}
 *   string 'nopin'      →  {nopin: true}
 *   string 'nopin,save' →  {nopin: true, save: true}    (comma-split, trimmed)
 *   array ['nopin']     →  {nopin: true}
 *   dict {nopin:true}   →  {nopin: true}    (shallow copy, lowercased, drops falsy)
 ***************************************************************************/
libVES.KeyStore.flags = function(input) {
    if (!input) return {};
    if (typeof input === 'string') input = input.split(',');
    if (Array.isArray(input)) return Object.fromEntries(
        input.map((k) => String(k).trim().toLowerCase()).filter(Boolean).map((k) => [k, true])
    );
    if (typeof input === 'object') return Object.fromEntries(
        Object.entries(input).filter(([, v]) => v).map(([k]) => [k.toLowerCase(), true])
    );
    return {};
};
