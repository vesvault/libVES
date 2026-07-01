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
 *         \___/              - VESrecovery (TM)
 *
 *
 * (c) 2018 - 2026 VESvault Corp
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
 * libVES.Scramble.js         libVES: VESrecovery scramble algorithms SSS1, RDX1.2
 *
 ***************************************************************************/
libVES.Scramble = {
    RDX: function(x) {
	this.size = x;
    }
};
// Default dispatcher used by setShadow (libVES-base.js): GF(256) Shamir (SSS1)
// for m <= 255 shares, integer RDX1.2 beyond that. An explicit optns.v still
// forces a specific scheme (resolved upstream in setShadow, honored here too).
libVES.Scramble.RDX.prototype = {
    explode: function(sc,ct,optns) {
	var impl = (optns && optns.v && libVES.Scramble.algo[optns.v]) || (ct <= 255 ? libVES.Scramble.SSS : libVES.Scramble.RDX12);
	return new impl(this.size).explode(sc,ct,optns);
    }
};
// Integer-domain Shamir (RDX 1.2): retained verbatim for legacy tokens and for
// the m >= 256 case. RDX1.2 is computationally secure (integer-domain Shamir
// with AES-CTR chaining), not information-theoretic — sound, just non-standard.
libVES.Scramble.RDX12 = function(x) {
    this.size = x;
};
libVES.Scramble.RDX12.prototype = {
    tag: 'RDX1.2',
    name: 'RDX 1.2 Shamir',
    getBases: function(n) {
	var rs = [];
	for (var b = 0; rs.length < n; b++) if (b % 4) rs.push(b);
	return rs;
    },
    getCv: function(b) {
	var rs = [libVES.Math.pad(1)];
	b = Number(b);
	for (var i = 1; i < this.size; i++) rs.push(libVES.Math.mul(rs[rs.length - 1], b));
	return rs;
    },
    toVector: function(sc) {
	var u = [sc];
	for (var i = 1; i < this.size; i++) {
	    u[i] = new Uint8Array(sc.length);
	    crypto.getRandomValues(u[i]);
	}
//	console.log('u',u);
	var v = [];
	for (var i = 0; i < this.size - 1; i++) v[i] = (function(ui,ui1) {
	    var kbuf = new Uint8Array(32);
	    kbuf.set(ui1);
	    return crypto.subtle.importKey('raw',kbuf,'AES-CTR',true,['encrypt','decrypt']).then(function(k) {
		return crypto.subtle.encrypt({name: 'AES-CTR', counter: new Uint8Array(16).fill(0), length: 128},k,ui).then(function(ctx) {
		    var ctxt = new Uint8Array(ctx);
		    var rs = new Uint8Array(ctxt.length + 1);
		    rs.set(ctxt);
		    rs[ctxt.length] = 1;
		    return rs;
		});
	    });
	})(u[i],u[i + 1]);
	var vi = new Uint8Array(u[i].length + 1);
	vi.set(u[i]);
	vi[u[i].length] = 1;
	v[i] = Promise.resolve(vi);
	return Promise.all(v);
    },
    fromVector: function(vec) {
	var v = [];
	var rs = new Promise(function(resolve,reject) {
	    for (var i = 0; i < vec.length; i++) {
		if (vec[i][vec[i].length - 1] != 1) return reject(new libVES.Error('Internal','Invalid recovery vector'));
		v[i] = vec[i].slice(0,vec[i].length - 1);
	    }
	    resolve(v[v.length - 1]);
	});
	for (var i = v.length - 2; i >= 0; i--) rs = rs.then((function(vi) {
	    return function(vi1) {
		var kbuf = new Uint8Array(32);
		kbuf.set(vi1);
		return crypto.subtle.importKey('raw',kbuf,'AES-CTR',true,['encrypt','decrypt']).then(function(k) {
		    return crypto.subtle.decrypt({name: 'AES-CTR', counter: new Uint8Array(16).fill(0), length: 128},k,vi).then(function(v) {
			return new Uint8Array(v);
		    });
		});
	    };
	})(v[i]));
	return rs;
    },
    scramble: function(vec,b) {
	return libVES.Math.mulv(vec,this.getCv(b));
    },
    explode: function(sc,ct,optns) {
	var self = this;
	return this.toVector(sc).then(function(v) {
	    var bs = self.getBases(ct);
	    var rs = [];
	    for (i = 0; i < bs.length; i++) rs[i] = {
		meta: (function(m) {
		    if (optns) {
			if (optns.t != null) m.t = optns.t;
			if (optns.shadow) for (var k in optns.shadow) m[k] = optns.shadow[k];
		    }
		    return m;
		})({
		    v: self.tag,
		    n: self.size,
		    b: bs[i]
		}),
		value: self.scramble(v,bs[i])
	    }
	    return rs;
	});
    },
    unscramble: function(tokens) {
	var matrix = [];
	var oidx = 0;
	for (var b in tokens) {
	    var row = this.getCv(b);
	    row.push(tokens[b]);
	    matrix.push(row);
	    if (matrix.length >= this.size) break;
	}
	if (matrix.length < this.size) throw new libVES.Error('Internal','Insufficient number of tokens to unscramble');
	return libVES.Math.matrixReduce(matrix).map(function(v,i) {
	    return libVES.Math.div(v[v.length - 1],v[i]);
	});
    },
    implode: function(tokens,then,okfn) {
	var self = this;
	var f = function(offs) {
	    var tks = {};
	    var tidx = 0;
	    var oidx = 0;
	    var more = false;
	    for (var i = 0; i < tokens.length; i++) {
		if (tidx >= self.size) {
		    more = true;
		    break;
		}
		if (tidx >= self.size - offs[oidx]) oidx++;
		else {
		    tks[tokens[i].meta.b] = tokens[i].value;
		    tidx++;
		}
	    }
	    var v = self.unscramble(tks);
	    var rs = self.fromVector(v);
	    if (then) rs = rs.then(then);
	    if (okfn) rs = rs.then(function(sc) {
		for (var i = 0; i < tokens.length; i++) okfn(tokens[i],!!tks[b] && !libVES.Math.cmp(tokens[i].value,self.scramble(v,tokens[i].meta.b)),i);
		return sc;
	    });
	    if (more) {
		var offs2 = offs.slice();
		var jmax = offs.length > 1 ? offs[offs.length - 2] : self.size;
		offs2[offs.length] = 0;
		for (var j = 1; j <= jmax; j++) rs = rs.catch((function(j) {
		    return function() {
			offs2[offs.length - 1] = j;
			return f(offs2);
		    };
		})(j));
	    }
	    return rs;
	};
	return f([0]);
    }
};
// Textbook Shamir secret sharing over GF(2^8) — the AES field (irreducible poly
// 0x11b, generator 0x03), wire tag SSS1. Each of the L secret bytes is shared with
// its own independent degree-(n-1) polynomial evaluated at the same x-coordinates
// 1..m (the byte-wise variant used by ssss and HashiCorp Vault). No AES chaining:
// over a real field the secret byte is simply the constant term.
libVES.Scramble.SSS = function(x) {
    this.size = x;
};
libVES.Scramble.SSS.prototype = {
    tag: 'SSS1',
    name: 'Shamir GF(256)',
    gf: function() {
	var g = libVES.Scramble.SSS._gf;
	if (g) return g;
	var exp = new Uint8Array(512);
	var log = new Uint8Array(256);
	for (var a = 1, i = 0; i < 255; i++) {
	    exp[i] = a;
	    log[a] = i;
	    var d = a << 1;
	    if (d & 0x100) d ^= 0x11b;
	    a = d ^ a;
	}
	for (var j = 255; j < 512; j++) exp[j] = exp[j - 255];
	return libVES.Scramble.SSS._gf = {exp: exp, log: log};
    },
    mul: function(a,b) {
	if (!a || !b) return 0;
	var g = this.gf();
	return g.exp[g.log[a] + g.log[b]];
    },
    div: function(a,b) {
	if (!a) return 0;
	var g = this.gf();
	return g.exp[g.log[a] + 255 - g.log[b]];
    },
    weights: function(xs,x0) {
	var w = [];
	for (var i = 0; i < xs.length; i++) {
	    var num = 1, den = 1;
	    for (var l = 0; l < xs.length; l++) if (l != i) {
		num = this.mul(num,x0 ^ xs[l]);
		den = this.mul(den,xs[i] ^ xs[l]);
	    }
	    w[i] = this.div(num,den);
	}
	return w;
    },
    combine: function(w,ys,len) {
	var rs = new Uint8Array(len);
	for (var j = 0; j < len; j++) {
	    var acc = 0;
	    for (var i = 0; i < w.length; i++) acc ^= this.mul(w[i],ys[i][j]);
	    rs[j] = acc;
	}
	return rs;
    },
    explode: function(sc,ct,optns) {
	var self = this;
	if (ct > 255) return Promise.reject(new libVES.Error('InvalidValue','GF(256) Shamir supports at most 255 shares'));
	var n = this.size;
	var L = sc.length;
	var rnd = new Uint8Array(L * (n - 1));
	if (n > 1) crypto.getRandomValues(rnd);
	var rs = [];
	for (var x = 1; x <= ct; x++) {
	    var val = new Uint8Array(L);
	    for (var j = 0; j < L; j++) {
		var acc = (n > 1) ? rnd[(n - 2) * L + j] : 0;
		for (var k = n - 2; k >= 1; k--) acc = self.mul(acc,x) ^ rnd[(k - 1) * L + j];
		val[j] = self.mul(acc,x) ^ sc[j];
	    }
	    rs.push({
		meta: (function(m) {
		    if (optns) {
			if (optns.t != null) m.t = optns.t;
			if (optns.shadow) for (var key in optns.shadow) m[key] = optns.shadow[key];
		    }
		    return m;
		})({
		    v: self.tag,
		    n: n,
		    b: x
		}),
		value: val
	    });
	}
	return Promise.resolve(rs);
    },
    implode: function(tokens,then,okfn) {
	var self = this;
	var n = this.size;
	if (tokens.length < n) return Promise.reject(new libVES.Error('Internal','Insufficient number of tokens to unscramble'));
	var xs = [], ys = [];
	for (var i = 0; i < n; i++) {
	    xs.push(Number(tokens[i].meta.b));
	    ys.push(tokens[i].value);
	}
	var L = ys[0].length;
	var rs = Promise.resolve(self.combine(self.weights(xs,0),ys,L));
	if (then) rs = rs.then(then);
	if (okfn) rs = rs.then(function(sc) {
	    for (var i = 0; i < tokens.length; i++) {
		var ok = i < n || !libVES.Math.cmp(tokens[i].value,self.combine(self.weights(xs,Number(tokens[i].meta.b)),ys,L));
		okfn(tokens[i],ok,i);
	    }
	    return sc;
	});
	return rs;
    }
};
libVES.Scramble.algo = {
    'RDX1.2': libVES.Scramble.RDX12,
    'SSS1': libVES.Scramble.SSS
};
