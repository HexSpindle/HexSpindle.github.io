// Tiny shared helpers for the raw-byte packet-parsing ops in this category.
import { decodeLatin1, parseHex } from '../../core/util.js';

/** Mirrors the Python ops' `parse_hex(data.decode("latin-1")) if fmt == "Hex" else data` pattern. */
export function rawOrHex(data, fmt) { return fmt === 'Hex' ? parseHex(decodeLatin1(data)) : data; }

export function hexSep(u8, sep = '') { return [...u8].map(b => b.toString(16).padStart(2, '0')).join(sep); }

export function ipv4Str(u8, off) { return `${u8[off]}.${u8[off + 1]}.${u8[off + 2]}.${u8[off + 3]}`; }
