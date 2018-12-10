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
 * libVES.Math.js             libVES: Internal math functions
 *
 ***************************************************************************/
libVES.Math = {
    pad: function(a,n) {
	if (isNaN(n)) n = 0;
	if (typeof(a) == 'number') {
	    var rs = [0];
	    for (var i = 0;;) {
		var f = (rs[i] = a & 0xff) & 0x80;
		a >>= 8;
		if (++i >= n && a == (f ? -1 : 0)) break;
	    }
	    return new Uint8Array(rs);
	}
	if (a.length >= n) return a;
	var rs = new Uint8Array(n);
	rs.set(a,0);
	var sgn = (a.length > 0 && (a[a.length - 1] & 0x80)) ? 0xff : 0;
	rs.fill(sgn,a.length);
	return rs;
    },
    add: function(a,b) {
	var l = (a.length > b.length ? a.length : b.length) + 1;
	a = this.pad(a,l);
	b = this.pad(b,l);
	var rs = new Uint8Array(l);
	var c = 0;
	var hi = 0;
	var hs = 0;
	for (var i = 0; i < l; i++) {
	    var v = a[i] + b[i] + c;
	    if ((rs[i] = v & 0xff) != (hs ? 0xff : 0)) hi = i;
	    hs = v & 0x80;
	    c = v >> 8;
	}
	return rs.slice(0,hi + 1);
    },
    sub: function(a,b) {
	return this.add(a,this.neg(b));
    },
    neg: function(a) {
	if (typeof(a) == 'number') return -a;
	var rs = new Uint8Array(a.length + 1);
	var c = 1;
	var o = 0;
	for (var i = 0; i < a.length; i++) {
	    var v = (~a[i] & 0xff) + c;
	    o = c & (v == 0x80);
	    rs[i] = v & 0xff;
	    c = v >> 8;
	}
	if (o) rs[i++] = 0;
	return rs.slice(0,i);
    },
    cmp: function(a,b) {
	var l = a.length > b.length ? a.length : b.length;
	a = this.pad(a,l);
	b = this.pad(b,l);
	var f = true;
	for (var i = l - 1; i >= 0; i--) {
	    if (f) {
		if ((a[i] ^ b[i]) & 0x80) return ((a[i] & 0x80) ? -1 : 1);
		f = false;
	    }
	    if (a[i] > b[i]) return 1;
	    if (a[i] < b[i]) return -1;
	}
	return 0;
    },
    isNeg: function(a) {
	if (typeof(a) == 'number') return a < 0;
	return a.length && (a[a.length - 1] & 0x80);
    },
    isZero: function(a) {
	if (typeof(a) == 'number') return a == 0;
	for (var i = 0; i < a.length; i++) if (a[i]) return false;
	return true;
    },
    mul: function(a,b) {
	var neg = false;
	if (this.isNeg(a)) {
	    neg = true;
	    a = this.neg(a);
	} else a = new Uint8Array(a);
	var int = typeof(b) == 'number';
	if (this.isNeg(b)) {
	    neg = !neg;
	    b = this.neg(b);
	} else if (!int) b = new Uint8Array(b);
	var sh_a = new libVES.Math.Shifter(a);
	if (!int) var sh_b = new libVES.Math.Shifter(b);
	var rs = this.pad(0,1);
	while (true) {
	    if ((int ? b : b[0]) & 0x01) rs = this.add(rs,a);
	    b = int ? b >> 1 : sh_b.shr();
	    if (this.isZero(b)) break;
	    a = sh_a.shl();
	}
	return neg ? this.neg(rs) : rs;
    },
    div_qr: function(a,b) {
	var neg = false;
	if (this.isNeg(a)) {
	    neg = true;
	    a = this.neg(a);
	} else a = new Uint8Array(a);
	if (typeof(b) == 'number') b = this.pad(b);
	if (this.isNeg(b)) {
	    neg = !neg;
	    b = this.neg(b);
	} else b = new Uint8Array(b);
	for (var l = b.length; l > 0 && !b[l - 1]; l--);
	if (!l) return null;
	var sh_b = new libVES.Math.Shifter(b);
	var q;
	for (var sh = (a.length - l + 1) * 8; sh >= 0; sh--) {
	    var d = sh_b.get(sh);
	    if (this.cmp(a,d) >= 0) {
		a = this.sub(a,d);
		if (!q) {
		    q = new Uint8Array(((sh + 1) >> 3) + 1);
		    q.fill(0);
		}
		q[sh >> 3] |= 1 << (sh & 7);
	    }
	}
	if (!q) q = new Uint8Array([0]);
	return {q: neg ? this.neg(q) : q, r: neg ? this.neg(a) : a};
    },
    div: function(a,b) {
	return this.div_qr(a,b).q;
    },
    mulv: function(v1,v2) {
	if (v1.length != v2.length) throw new libVES.Error('Internal','mulv: vectors have different size');
	var rs = this.pad(0);
	for (var i = 0; i < v1.length; i++) rs = this.add(rs,this.mul(v1[i],v2[i]));
	return rs;
    },
    matrixReduce: function(matrix) {
	var m = [];
	for (var i = 0; i < matrix.length; i++) {
	    m[i] = [];
	    for (var j = 0; j < matrix[i].length; j++) m[i][j] = matrix[i][j];
	}
	for (var i = 0; i < m.length; i++) {
	    var q = m[i][i];
	    for (var ii = 0; ii < m.length; ii++) if (ii != i) {
		var p = m[ii][i];
		for (var j = 0; j < m[i].length; j++) m[ii][j] = this.sub(this.mul(m[ii][j],q),this.mul(m[i][j],p));
	    }
	}
	return m;
    },
    
    hexChars: '0123456789abcdef',
    hex: function(a) {
	var rs = [];
	for (var i = 0; i < a.length; i++) rs[a.length - i - 1] = this.hexChars[a[i] >> 4] + this.hexChars[a[i] & 0x0f];
	return rs.join('');
    },
    Shifter: function(a) {
	this.shifts = [a];
	this.offs = 0;
    }
};
libVES.Math.Shifter.prototype = {
    get: function(offs) {
	var self = this;
	var sh = offs & 7;
	var bs = offs >> 3;
	var shf;
	var v = (shf = function(sh) {
	    if (!self.shifts[sh]) {
		if (sh <= 0) throw new libVES.Error('Internal','Shifter offset is not available');
		var prev = shf(sh - 1);
		self.shifts[sh] = libVES.Math.add(prev,prev);
	    }
	    return self.shifts[sh];
	})(sh);
	if (bs <= 0) return v.length + bs >= 1 ? v.slice(-bs) : libVES.Math.pad(v[v.length - 1] & 0x80 ? -1 : 1);
	var rs = new Uint8Array(v.length + bs);
	rs.fill(0,0,bs);
	rs.set(v,bs);
	return rs;
    },
    shl: function() {
	return this.get(++this.offs);
    },
    shr: function() {
	return this.get(--this.offs);
    }
};
