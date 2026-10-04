import { module } from './_cat.js';
import { toPem } from './_pem.js';

const EC_CURVES = ['P-256', 'P-384', 'P-521'];

module('JWK to PEM', 'Converts a JSON Web Key (RSA / EC) to PEM.', [],
  async (t) => {
    let j;
    try { j = JSON.parse(t); } catch (e) { throw new Error(`Not valid JSON: ${e.message}`); }
    if (typeof j !== 'object' || j === null || Array.isArray(j) || !('kty' in j)) {
      throw new Error('Not a JWK: expected a JSON object with a \'kty\' field (e.g. "kty": "RSA")');
    }
    const isPriv = 'd' in j;
    // Only the raw key material matters for a PEM/DER export - PEM has no concept of restricted key
    // usage - but importKey() validates the requested algorithm/usages against the JWK's own
    // use/key_ops/alg hints and rejects anything that doesn't match (e.g. an RSA-OAEP encryption key
    // would be rejected for the sign/verify usage below). Strip those hints so any RSA/EC JWK
    // (signing, encryption, or key-agreement) converts regardless of what it was issued for.
    j = { ...j };
    delete j.use; delete j.key_ops; delete j.alg;
    let algo, usages;
    if (j.kty === 'RSA') {
      algo = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      usages = isPriv ? ['sign'] : ['verify'];
    } else if (j.kty === 'EC') {
      if (!EC_CURVES.includes(j.crv)) throw new Error(`Unsupported EC curve: ${JSON.stringify(j.crv)} (expected P-256, P-384 or P-521)`);
      algo = { name: 'ECDSA', namedCurve: j.crv };
      usages = isPriv ? ['sign'] : ['verify'];
    } else {
      throw new Error(`Unsupported kty: ${JSON.stringify(j.kty)} (expected RSA or EC)`);
    }
    let key;
    try {
      key = await crypto.subtle.importKey('jwk', j, algo, true, usages);
    } catch (e) {
      throw new Error(`Invalid or incomplete JWK: ${e.message}`);
    }
    if (isPriv) return toPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)), 'PRIVATE KEY');
    return toPem(new Uint8Array(await crypto.subtle.exportKey('spki', key)), 'PUBLIC KEY');
  }, { text: true });
