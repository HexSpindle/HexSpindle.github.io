import { module } from './_cat.js';

const MAXLINESIZE = 76;

// Mirrors CPython's binascii.b2a_qp (quotetabs=False, istext=True, header=False), which is what
// quopri.encodestring() delegates to.
module('To Quoted Printable', 'Encodes data as MIME Quoted-Printable.', [],
  (data) => {
    let crlf = 0;
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 10) { if (i > 0 && data[i - 1] === 13) crlf = 1; break; }
    }
    const out = [];
    const pushHex = (b) => { const h = b.toString(16).toUpperCase().padStart(2, '0'); out.push(0x3d, h.charCodeAt(0), h.charCodeAt(1)); };
    let linelen = 0, i = 0;
    const n = data.length;
    while (i < n) {
      const b = data[i];
      const needsEscape = b > 126 || b === 0x3d ||
        (b === 0x2e && linelen === 0 && (i + 1 === n || data[i + 1] === 10 || data[i + 1] === 13 || data[i + 1] === 0)) ||
        ((b === 9 || b === 32) && i + 1 === n) ||
        (b < 33 && b !== 13 && b !== 10 && b !== 9 && b !== 32);
      if (needsEscape) {
        if (linelen + 3 >= MAXLINESIZE) {
          out.push(0x3d); if (crlf) out.push(13); out.push(10);
          linelen = 0;
        }
        pushHex(b);
        i++; linelen += 3;
      } else if (b === 10 || (i + 1 < n && b === 13 && data[i + 1] === 10)) {
        linelen = 0;
        if (out.length && (out[out.length - 1] === 32 || out[out.length - 1] === 9)) {
          const ch = out.pop();
          pushHex(ch);
        }
        if (crlf) out.push(13);
        out.push(10);
        i += b === 13 ? 2 : 1;
      } else {
        if (i + 1 !== n && data[i + 1] !== 10 && linelen + 1 >= MAXLINESIZE) {
          out.push(0x3d); if (crlf) out.push(13); out.push(10);
          linelen = 0;
        }
        linelen++;
        out.push(b); i++;
      }
    }
    return new Uint8Array(out);
  });
