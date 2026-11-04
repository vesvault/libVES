/*
 * End-to-end ECDH through the Node bundle, and across two bundles.
 *
 *   node bundle-test.js make  <libVES.node.js> <out.json>
 *   node bundle-test.js check <libVES.node.js> <in.json>
 *
 * make: keys on several curves, an encrypt/decrypt round trip on each, and
 * the exported private key read back by native openssl. check: another
 * bundle imports those keys and decrypts the ciphertexts, so an engine
 * change can be shown to read what the previous release wrote.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
"use strict";
const [mode, bundle, file] = process.argv.slice(2);
const path = require("path");
const libVES = require(path.resolve(bundle));
const crypto = require("crypto"), fs = require("fs"), { execFileSync } = require("child_process");
const curves = ["secp256k1", "brainpoolP384r1", "secp224r1", "sect283k1", "P-521"];
const pemFile = path.join(path.dirname(path.resolve(file)), "k.pem");
let bad = 0;

(async () => {
  if (mode === "make") {
    const out = [];
    for (const c of curves) {
      try {
        const kp = await libVES.Algo.ECDH.generate({ namedCurve: c });
        const msg = crypto.randomBytes(100);
        const ct = await libVES.Algo.ECDH.encrypt(kp.publicKey, msg);
        const pt = await libVES.Algo.ECDH.decrypt(kp.privateKey, ct);
        const pem = await libVES.Algo.ECDH.export(kp.privateKey, { opentext: true });
        fs.writeFileSync(pemFile, pem);
        let native;
        try {
          native = execFileSync("openssl", ["pkey", "-in", pemFile, "-noout", "-text"]).toString()
            .match(/(ASN1 OID|NIST CURVE): (.*)/g).join(", ");
        } catch (e) { native = "NATIVE OPENSSL CANNOT READ IT"; bad++; }
        const rt = Buffer.compare(Buffer.from(pt), msg) === 0;
        if (!rt) bad++;
        console.log(`${c.padEnd(16)} round trip ${rt ? "ok" : "FAIL"}; ${pem.split("\n")[0].trim()}; native: ${native}`);
        out.push({ c, pem, ct: Buffer.from(ct).toString("base64"), msg: msg.toString("base64") });
      } catch (e) {
        console.log(`${c.padEnd(16)} cannot generate here: ${e.message || e}`);
      }
    }
    fs.writeFileSync(file, JSON.stringify(out));
  } else {
    for (const r of JSON.parse(fs.readFileSync(file))) {
      try {
        const k = await libVES.Algo.ECDH.import(r.pem);
        const pt = await libVES.Algo.ECDH.decrypt(k, Buffer.from(r.ct, "base64"));
        const ok = Buffer.compare(Buffer.from(pt), Buffer.from(r.msg, "base64")) === 0;
        if (!ok) bad++;
        console.log(`${r.c.padEnd(16)} decrypts the other bundle's ciphertext with its exported key: ${ok ? "ok" : "FAIL"}`);
      } catch (e) {
        bad++;
        console.log(`${r.c.padEnd(16)} FAIL ${e.message || e}`);
      }
    }
  }
  console.log(bad ? `${bad} FAILED` : "ALL PASSED");
  process.exit(bad ? 1 : 0);
})();
