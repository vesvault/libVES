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
 * (c) 2018 VESvault Corp
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
 * libVES.Scramble.js         libVES: VESrecovery algorithm RDX1.2
 *
 ***************************************************************************/
libVES.Scramble = {
    RDX: function(x) {
	this.size = x;
    }
};
libVES.Scramble.RDX.prototype = {
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
	    window.crypto.getRandomValues(u[i]);
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
		    if (optns instanceof Object) for (var k in optns) if (m[k] === undefined) m[k] = optns[k];
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
libVES.Scramble.algo = {
    'RDX1.2': libVES.Scramble.RDX
};
