/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES.Watch: Event Observer
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2024 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/


libVES.subtle = function(optns) {
    if (!(optns instanceof Object)) {
        let uri = String(optns);
        optns = uri.includes('/') ? libVES.Vault.toRef(uri) : {domain: uri};
    }
    return new libVES(optns).subtle();
};

libVES.prototype.subtle = function(ref) {
    return new libVES.Vault((ref || this), this);
};

libVES.EventTarget = class extends EventTarget {
    watchFields() {
        return {vaultKey: {id: true, user: {id: true, email: true}, externals: {domain: true, externalId: true}}, vaultItem: {id: true, type: true, deleted: true, vaultKey: {id: true, type: true, externals: {domain: true, externalId: true}, user: {id: true, email: true}}, file: {externals: {domain: true, externalId: true}, creator: true}}, authorSession: {id: true, vaultKey: {id: true, type: true, externals: {domain: true, externalId: true}}, domain: true, user: {email: true}, remote: true, userAgent: true}, session: {id: true, vaultKey: {id: true}, user: {id: true}, remote: true, userAgent: true}};
    }

    dispatchEvent(ev) {
        if (!ev) return;
        super.dispatchEvent(ev);
        if (this['on' + ev.type]) try { this['on' + ev.type](ev) } catch (er) { console.log(er); }
    }

    start(optns) {
        if (!this.watch) {
            let tr = this._eventTracker();
            if (optns === false) optns = {replay: true};
            else if (optns != null && !isNaN(optns)) optns = {startEvent: Number(optns)};
            else if (!(optns instanceof Object)) optns = {};
            if (optns.startEvent == null) optns.startEvent = -1;
            this.watch = this.createWatch(optns);
            this.watch.eventfn = (ev) => (this.eventClear = this.eventClear.then(() => tr._event(ev).then((ev) => this.dispatchEvent(ev)).catch((er) => console.log(er))));
            this.eventClear = optns.replay ? this.replay((optns.replay instanceof Object) ? optns.replay : optns).then((evs) => Promise.all(evs.map((ev) => this.dispatchEvent(ev)))) : Promise.resolve();
            return this.watch.start(optns.startEvent).then((v) => (v || this.badauth().then(() => this.watch.start(startEvent)))).catch((er) => {
              this.watch = null;
              throw er;
            });
        } else throw new libVES.Error.InvalidValue('The watch is already started');
    }

    stop() {
        if (this.watch) return Promise.resolve(this.watch.stop()).then(() => this.eventClear).then(() => true).finally(() => this.watch = null);
        return Promise.resolve(null);
    }

    events(optns) {
        let tr = this._eventTracker();
        return this.createWatch(optns).getEvents(0, 0).then((evs) => (evs ? evs.reduce((res, ev) => res.then((res) => tr._event(ev, false).then((ev) => ((ev && res.push(ev)), res))), Promise.resolve([])) : this.badauth().then(() => this.events())));
    }

    toJSON() {
        return this.uri();
    }
};

libVES.Vault = class extends libVES.EventTarget {
    constructor(ref, ves, fields) {
        super();
        this.init(libVES.Vault.toRef(ref, ves), ves, fields);
    }

    init(ref, ves, fields) {
        fields ||= {};
        if (ref.externalId) fields.externals = [{domain: (this.domain = String(ref.domain)), externalId: (this.externalId = String(ref.externalId))}];
        this.email = ref.email || '';
        if (ref.email) fields.email = this.email;
        if (ref.version) this.version = fields.id = Number(ref.version);
        if (!fields.id) fields.type = this.externalId ? 'secondary' : 'current';
        this.vaultKey = new libVES.VaultKey(fields, ves);
        delete(this.admin);
    };

    item(ref) {
        return new libVES.Item(ref, this);
    };

    vault(ref) {
        if (!ref) return null;
        return new libVES.Vault(ref, this.vaultKey.VES);
    }

    entries(optns) {
        const flds = {encData: true, vaultItem: {type: true, file: {externals: true, creator: {id: true, email: true}}, deleted: true, vaultKey: {type: true, externals: true, user: true}, type: true, meta: true}};
        const getfn = () => this.vaultKey.getField('vaultEntries', flds, true).then((data) => libVES.Util.fillUndefs(data, flds));
        if (!this._entriesCache) (this._entriesCache = getfn().then((entries) => (entries || this.badauth().then(getfn)))).catch(() => null).finally(() => this._entriesCache = null);
        return this._entriesCache;
    };

    objects(optns) {
        let found = {items: {}, vaults: {}};
        return this.entries(optns).then((entries) => Promise.all((entries || []).map((entry) => {
            const ext = entry.vaultItem?.file?.externals?.[0];
            if (ext) {
                if (entry.vaultItem.deleted) return null;
                let d = (found.items[ext.domain] ||= {});
                return d[ext.externalId] ? null : (d[ext.externalId] = new libVES.Item(ext, this, entry.vaultItem));
            }
            const vkey = entry.vaultItem?.vaultKey;
            const kext = vkey?.externals?.[0];
            if (kext && vkey.type == 'secondary' && entry.vaultItem.type == 'password') {
                let d = (found.vaults[kext.domain] ||= {});
                    return d[kext.externalId] ? null : (d[kext.externalId] = new libVES.Vault(kext, this.vaultKey.VES, vkey));
            }
        }))).then((objs) => objs.filter((obj) => obj));
    };

    items(optns) {
        return this.objects(optns).then((objs) => objs.filter((obj) => (obj instanceof libVES.Item)));
    }

    vaults(optns) {
        return this.objects(optns).then((objs) => objs.filter((obj) => (obj instanceof libVES.Vault)));
    }

    _setunlock(reauth) {
        this.current = true;
        this.owner = this.externalId[0] != '!';
        this.lock(600);
        let rf;
        if (reauth !== false) (rf = (tmout) => {
            this.refreshTmout = setTimeout(() => {
                this.vaultKey.loadFields({encSessionToken: true}, true, {token: ''}).then((flds) => this.vaultKey.setFields(flds)).then(() => this.vaultKey.getSessionToken()).then((tk) => {
                    this.vaultKey.VES.token = tk;
                    rf();
                }).catch((er) => {
                    console.log(er);
                    rf(60000);
                });
            }, (tmout || 14400000));
        })();
        return this;
    }

    unlock(optns) {
        if (this.lockInProgress) return this.lock().then(() => this.unlock(optns));
        if (optns && !(optns instanceof Object)) optns = libVES.Vault.toRef(optns, this.vaultKey.VES);
        if (optns?.veskey) return this.vaultKey.VES.logout().then(() => {
            let ves = new libVES(optns);
            delete(ves.veskey);
            return ((reauth) => ves.unlock(String(optns.veskey)).then(() => this.init(ves, ves)).then(() => this._setunlock(reauth)))(!this.vaultKey.VES.token);
        });
        return this.vaultKey.VES.unlock().catch((er) => {
            let mode = optns?.mode || 'delegate';
            switch (mode) {
                case 'delegate': return this.vaultKey.VES.delegate(optns).then((ves) => this.init(ves, ves));
                case 'flow': return this.vaultKey.VES.flow(true, optns).then((ves) => this.init(ves, ves));
                case 'veskey': throw new libVES.Error.InvalidValue('No veskey provided');
                default: throw new libVES.Error.InvalidValue('Unknown unlock mode: ' + mode + ', expected: delegate|flow');
            }
        }).then(() => this._setunlock());
    }

    unlocked(optns) {
        return this.vaultKey.VES.unlock().catch((er) => {
            if (optns?.mode != 'flow') throw er;
            return this.vaultKey.VES.flow(false, optns).then((ves) => this.init(ves, ves)).then(() => this._setunlock());
        }).then(() => true).catch((er) => false);
    }

    anonymous(optns) {
        if (!(optns instanceof Object)) {
            if (optns && typeof(optns) == 'string') optns = {veskey: optns};
            else optns = {};
        }
        if (!optns.veskey) return Promise.reject(libVES.Error.InvalidValue('Required: veskey'));
        if (!this.vaultKey.VES.domain) return Promise.reject(libVES.Error.InvalidValue('Cannot create an anonymous vault without a VES domain'));
        this.vaultKey.VES.logout();
        return (optns.externalId ? Promise.resolve(this.vaultKey.VES.externalId = optns.externalId) : crypto.subtle.digest('sha-256', libVES.Util.StringToByteArray('libVES.subtle\0' + this.vaultKey.VES.domain + '\0' + optns.veskey)).then((hash) => {
            const hex = '0123456789abcdef';
            let xid = new Uint8Array(hash).reduce(((v, e) => v + hex[e >> 4] + hex[e & 0x0f]), '!');
            this.vaultKey.VES.externalId = xid;
        })).then(() => this.vaultKey.VES.unlock(optns.veskey).catch((er) => {
            if (er?.code == 'NotFound') return this.vaultKey.VES.setAnonymousKey(optns.veskey, optns);
            else throw er;
        })).then(() => this.init(this.vaultKey.VES, this.vaultKey.VES)).then(() => this._setunlock());
    }

    lock(tmout) {
        this.lockInProgress = false;
        clearTimeout(this.lockTmout);
        this.lockTmout = null;
        if (tmout > 0) {
            if (tmout > 3600) tmout = 3600;
            this.lockTmout = setTimeout(() => {
                this.lockInProgress = true;
                this.dispatchEvent(new libVES.CustomEvent('authexpire', {detail: {vault: this}}));
                if (this.lockInProgress) this.lock();
            }, tmout * 1000);
            return Promise.resolve(true);
        }
        clearTimeout(this.refreshTmout);
        this.refreshTmout = null;
        this.stop();
        return this.vaultKey.VES.logout();
    }

    random() {
        return this.vaultKey.VES.generateVESkey();
    }

    static toRef(value, ves) {
        switch (typeof(value)) {
            case 'object':
                return value;
            case 'number':
                value = String(value);
            case 'string':
                let uri = new URL(value, "ves://" + (ves && ves.domain ? ves.domain : ''));
                if (uri.protocol != 'ves:') throw new libVES.Error.InvalidValue("Invalid schema: '" + uri.protocol + "', expected 'ves:'");
                let p = uri.pathname.split('/');
                let id = p.length > 1 ? decodeURIComponent(p[1]) : '';
                let ref = uri.host ? {domain: uri.host, externalId: id} : {version: Number(id)};
                if (p[2] != null) ref.email = decodeURIComponent(p[2]);
                if (uri.password) ref.veskey = uri.password;
                return ref;
        }
    };

    static toRefs(refs, ves, owner) {
        if (!refs) return [];
        if (!(refs instanceof Array)) refs = [refs];
        refs = refs.map((ref) => libVES.Vault.toRef(ref, ves)).filter((ref) => ref);
        if (owner) {
            if (!ves.externalId) throw new libVES.Error.Unauthorized('The vault is locked');
            refs.push({domain: ves.domain, externalId: ves.externalId});
        }
        return refs;
    }

    static toUri(ref, short) {
        if (ref.externalId && short) return (ref.domain == short ? '' : '//' + encodeURIComponent(ref.domain) + '/') + encodeURIComponent(ref.externalId).replaceAll('%40', '@');
        let uri = ref.externalId ?  "ves://" + encodeURIComponent(ref.domain) + "/" + encodeURIComponent(ref.externalId) : "ves://" + (ref.version ? "/" + String(Number(ref.version)) : encodeURIComponent(ref.domain ?? '') + "/");
        if (ref.email != null) uri += '/' + encodeURIComponent(ref.email);
        return uri;
    }

    uri() {
        if (!this.externalId && !this.version && !this.email) return null;
        return libVES.Vault.toUri(this);
    }

    short() {
        return libVES.Vault.toUri(this, this.vaultKey.VES.domain);
    }

    badauth() {
        const ves = this.vaultKey.VES;
        if (!this.externalId || (this.externalId == ves.externalId && this.domain == ves.domain)) return Promise.reject(new libVES.Error.InvalidKey('Not authorized for this key'));
        return this.vaultKey.getFields({encSessionToken: true, type: true, algo: true, publicKey: true, privateKey: true, vaultItems: {type: true, vaultEntries: {vaultKey : {id: true}, encData: true}, meta: true}}).then(() => {
            const ves2 = new libVES({domain: this.domain, externalId: this.externalId});
            ves2.vaultKey = Promise.resolve(this.vaultKey);
            ves2.unlockedKeys = ves.unlockedKeys;
            ves2.pendingKeys = ves.pendingKeys;
            this.vaultKey.VES = ves2;
            return ves2.unlock();
        });
    }

    createWatch() {
        let w = new libVES.Watch(this.vaultKey);
        w.fields = {vaultItem: {id: true, type: true, deleted: true, vaultKey: {id: true, type: true, algo: true, publicKey: true, externals: {domain: true, externalId: true}, user: {id: true, email: true}}, file: {externals: {domain: true, externalId: true}, creator: true}, meta: true}, authorSession: {vaultKey: {id: true, externals: {domain: true, externalId: true}, user: {email: true}, type: true}, domain: true, user: {email: true}, remote: true, userAgent: true}, session: {id: true, remote: true, userAgent: true, vaultKey: {id: true}, user: {id: true}}};
        return w;
    }

    replay(optns) {
        return this.objects(optns).then((objs) => Promise.all(objs.map((obj) => {
            if (obj instanceof libVES.Item) return new libVES.CustomEvent('itemadd', {detail: {replay: true, item: obj, share: this}});
            else if (obj instanceof libVES.Vault) return new libVES.CustomEvent('vaultadd', {detail: {replay: true, vault: obj, share: this}});
        })));
    }

    password() {
        return this.vaultKey.getVaultItems().then((vitems) => {
            if (!vitems) return this.badauth().then(() => this.password());
            return vitems.reduce((p, vitem) => p.catch((e) => vitem.getType().then((type) => (type == 'password' ? vitem.getId().then((id) => this.item({version: id})) : Promise.reject(e)))), Promise.reject(new libVES.Error.NotFound('No password item found')));
        });
    }

    verify() {
        if (this.current !== undefined) return Promise.resolve(this);
        return this.vaultKey.VES.usersToKeys([(this.externalId ? {domain: this.domain, externalId: this.externalId} : this.email)]).then((vkeys) => Promise.all(vkeys.map((vkey) => vkey.getFields(vkey.id ? {id: true, type: true} : {type: true}))).then((flds) => flds.reduce((res, fld, idx) => {
            if (res) return res;
            if (this.version) return this.version == fld.id ? vkeys[idx] : null;
            switch (fld.type) {
                case 'secondary': case 'current': case 'temp': return vkeys[idx];
            }
        }, null))).then((vkey) => {
            if (!vkey) throw new libVES.Error.NotFound('Cannot find or create a matching key');
            return vkey.getType().then((type) => {
                this.current = (type == 'current' || type == 'secondary');
                this.owner = (this.externalId != null && this.externalId == vkey.VES.externalId && this.domain == vkey.VES.domain) || (!!this.email && this.email == vkey.VES.email);
                this.vaultKey = vkey;
                return this;
            });
        });
    }

    _eventTracker() {
        return new libVES.EventTracker(this);
    }

    toString() {
        return 'libVES.Vault(' + (this.uri() ?? '[pending]') + ')';
    }

};

libVES.Author = class {
    constructor(sess, ves) {
        this.sessid = sess.id;
        if (sess.vaultKey?.externals?.[0]) this.vault = new libVES.Vault(sess.vaultKey.externals[0], ves);
        else if (sess.user?.email) this.vault = new libVES.Vault({email: sess.user.email}, ves);
        this.remote = sess.remote;
        this.userAgent = sess.userAgent;
    }
    toString() {
        return 'libVES.Author(' + (this.sessid ?? '') + ')';
    }
    toJSON() {
        return this.sessid;
    }
};

libVES.CustomEvent = class extends CustomEvent {
    toString() {
        return 'libVES.CustomEvent(' + this.type + (this.detail?.id ? '[' + this.detail.id + ']' : '') + (this.detail?.at ? ' @' + this.detail.at : '') + ')';
    }
    toJSON() {
        return this.detail?.id;
    }
};

libVES.EventTracker = class {
    constructor(vault, share) {
        this.vault = vault;
        this.share = share;
        this.items = {};
    }

    _event(e, attn) {
        const event = (type, detail) => {
            detail.event = e;
            return e.getFields({id: true, recordedAt: true, authorSession: {vaultKey: {id: true, externals: {domain: true, externalId: true}, user: {email: true}}, user: {email: true}, domain: true, remote: true, userAgent: true}}).then((flds) => {
                detail.id = flds?.id;
                if (flds?.recordedAt) detail.at = new Date(flds.recordedAt);
                detail.author = new libVES.Author((flds?.authorSession ?? {}), this.vault.vaultKey.VES);
            }).catch(() => null).then(() => new libVES.CustomEvent(type, {detail: detail}));
        }
        return e.getType().then((type) => {
            const itemfn = (ac, attn, sh) => e.getVaultItem().then((vitem) => vitem.getType().then((itype) => {
                switch (itype) {
                    case 'string': case 'file':
                        return vitem.getFields({id: true, file: {externals: {domain: true, externalId: true}}, deleted: true, type: true, meta: true}).then((flds) => {
                            let ext = flds?.file?.externals?.[0];
                            if (!ext) return null;
                            let item = new libVES.Item({domain: ext.domain, externalId: ext.externalId, version: flds.id}, this.vault, flds);
                            let ids = (this.items[item.uri()] ||= []);
                            let idx = ids.indexOf(flds.id);
                            if (idx < 0 && (flds.deleted === false || (ac == 'create' || ac == 'add'))) ids.unshift(flds.id), idx = 0;
                            return event((idx == 0 ? '' : 'old') + 'item' + ac, {item: item, share: sh});
                        });
                    case 'password':
                        return vitem.getFields({vaultKey: {type: true, externals: {domain: true, externalId: true}}}).then((flds) => {
                            switch (flds?.vaultKey?.type) {
                                case 'secondary':
                                    return event('vault' + ac, {vault: this.vault.vault(flds.vaultKey.externals?.[0]), share: sh});
                                default:
                                    if (attn) return vitem.getVaultKey().then((vkey) => this.vault.vaultKey.VES.attnVaultKeys([vkey])).catch((e) => console.log(e)).then(() => null);
                            }
                        });
                }
            }));
            const sharefn = () => (this.share ? e.getVaultKey().then((vkey) => vkey.getFields({id: true, type: true, externals: {domain: true, externalId: true}, user: {id: true, email: true}}).then((flds) => {
                let f = flds?.externals?.[0] ? flds.externals[0] : (flds?.user?.email ? {email: flds.user.email} : {});
                f.version = flds.id;
                let vault = this.vault.vault(f);
                vault.current = (f.externals && flds.type == 'secondary') || (f.email && flds.type == 'current');
                return vault;
            })) : Promise.resolve(this.vault));
            switch (type) {
                case 'vaultEntry.deleted':
                    return sharefn().then((sh) => itemfn('remove', false, sh));
                case 'vaultEntry.created':
                    return sharefn().then((sh) => itemfn('add', attn !== false, sh));
                case 'vaultItem.deleted':
                    return itemfn('delete');
                case 'vaultItem.created':
                    return itemfn('create');
                case 'vaultItem.listening':
                    return itemfn('change');
                case 'session.created':
                    return e.getFields({session: {id: true, remote: true, userAgent: true, vaultKey: {id: true}, user: {id: true}}}).then((flds) => {
                        if (!flds?.session) return null;
                        let ses = new libVES.Author(flds.session, this.vault.vaultKey.VES);
                        ses.vault = this.vault;
                        return event('sessioncreate', {vault: this.vault, session: ses});
                    });
            }
        }).catch((er) => (console.log(er), event('error', {error: er})));
    }
};
