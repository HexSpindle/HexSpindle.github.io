// Minimal SSH KEXINIT parser, shared by HASSH Client/Server Fingerprint - mirrors core/ssh.py.
const NAMES = ['kex_algorithms', 'server_host_key_algorithms', 'encryption_algorithms_client_to_server', 'encryption_algorithms_server_to_client',
  'mac_algorithms_client_to_server', 'mac_algorithms_server_to_client', 'compression_algorithms_client_to_server',
  'compression_algorithms_server_to_client', 'languages_client_to_server', 'languages_server_to_client'];

export function parseKexinit(data) {
  let b = data;
  // tolerate being handed a full SSH binary packet (4-byte length + 1-byte padlen prefix) or a bare payload
  if (b.length > 5 && b[5] === 20) {
    const padlen = b[4];
    b = (b.length - padlen > 5) ? b.subarray(5, b.length - padlen) : b.subarray(5);
  }
  if (!b.length || b[0] !== 20) throw new Error('Not an SSH_MSG_KEXINIT packet (expected message code 20)');
  let i = 1 + 16; // msg code + 16-byte cookie
  const out = {};
  const td = new TextDecoder('ascii', { fatal: false });
  for (const name of NAMES) {
    const n = (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]) >>> 0;
    i += 4;
    out[name] = latin1ToAsciiReplace(b.subarray(i, i + n));
    i += n;
  }
  return out;
}

// Python's .decode("ascii", errors="replace") swaps each non-ASCII byte for U+FFFD; TextDecoder's
// "ascii" label is actually windows-1252 per the WHATWG spec, so replicate it by hand instead.
function latin1ToAsciiReplace(b) {
  let s = '';
  for (const c of b) s += c < 0x80 ? String.fromCharCode(c) : '�';
  return s;
}
