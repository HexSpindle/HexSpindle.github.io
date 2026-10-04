import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { encodeUtf8, decodeUtf8, decodeLatin1 } from '../../core/util.js';

export const ENCODINGS = ['UTF-8', 'UTF-16LE', 'UTF-16BE', 'UTF-16', 'UTF-32LE', 'UTF-32BE', 'UTF-7', 'ASCII', 'ISO-8859-1 (Latin1)', 'ISO-8859-2', 'ISO-8859-5', 'ISO-8859-7', 'ISO-8859-15',
  'Windows-1250', 'Windows-1251', 'Windows-1252', 'Windows-1253', 'Windows-1256', 'KOI8-R', 'KOI8-U', 'Shift_JIS', 'EUC-JP', 'ISO-2022-JP', 'GBK', 'GB18030', 'Big5', 'EUC-KR',
  'CP437', 'CP850', 'CP866', 'MacRoman', 'IBM EBCDIC (CP037)', 'IBM EBCDIC (CP500)'];

// Single-byte sets whose bytes 0x00-0x7F are plain ASCII: byte 0x80+i -> this Unicode code point
// (-1 = unassigned in that set). TextDecoder/TextEncoder can't be used for these: TextEncoder only
// ever produces UTF-8, and several of these labels are aliased by the WHATWG Encoding spec to
// windows-1252 or otherwise don't round-trip the way the equivalent Python codec does, so the
// tables (lifted from Python's own codecs) are used for both directions instead.
const HI = {
  'ISO-8859-2': [128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,260,728,321,164,317,346,167,168,352,350,356,377,173,381,379,176,261,731,322,180,318,347,711,184,353,351,357,378,733,382,380,340,193,194,258,196,313,262,199,268,201,280,203,282,205,206,270,272,323,327,211,212,336,214,215,344,366,218,368,220,221,354,223,341,225,226,259,228,314,263,231,269,233,281,235,283,237,238,271,273,324,328,243,244,337,246,247,345,367,250,369,252,253,355,729],
  'ISO-8859-5': [128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,173,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1101,1102,1103,8470,1105,1106,1107,1108,1109,1110,1111,1112,1113,1114,1115,1116,167,1118,1119],
  'ISO-8859-7': [128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,8216,8217,163,8364,8367,166,167,168,169,890,171,172,173,-1,8213,176,177,178,179,900,901,902,183,904,905,906,187,908,189,910,911,912,913,914,915,916,917,918,919,920,921,922,923,924,925,926,927,928,929,-1,931,932,933,934,935,936,937,938,939,940,941,942,943,944,945,946,947,948,949,950,951,952,953,954,955,956,957,958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,973,974,-1],
  'ISO-8859-15': [128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,8364,165,352,167,353,169,170,171,172,173,174,175,176,177,178,179,381,181,182,183,382,185,186,187,338,339,376,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255],
  'Windows-1250': [8364,-1,8218,-1,8222,8230,8224,8225,-1,8240,352,8249,346,356,381,377,-1,8216,8217,8220,8221,8226,8211,8212,-1,8482,353,8250,347,357,382,378,160,711,728,321,164,260,166,167,168,169,350,171,172,173,174,379,176,177,731,322,180,181,182,183,184,261,351,187,317,733,318,380,340,193,194,258,196,313,262,199,268,201,280,203,282,205,206,270,272,323,327,211,212,336,214,215,344,366,218,368,220,221,354,223,341,225,226,259,228,314,263,231,269,233,281,235,283,237,238,271,273,324,328,243,244,337,246,247,345,367,250,369,252,253,355,729],
  'Windows-1251': [1026,1027,8218,1107,8222,8230,8224,8225,8364,8240,1033,8249,1034,1036,1035,1039,1106,8216,8217,8220,8221,8226,8211,8212,-1,8482,1113,8250,1114,1116,1115,1119,160,1038,1118,1032,164,1168,166,167,1025,169,1028,171,172,173,174,1031,176,177,1030,1110,1169,181,182,183,1105,8470,1108,187,1112,1029,1109,1111,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1101,1102,1103],
  'Windows-1252': [8364,-1,8218,402,8222,8230,8224,8225,710,8240,352,8249,338,-1,381,-1,-1,8216,8217,8220,8221,8226,8211,8212,732,8482,353,8250,339,-1,382,376,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255],
  'Windows-1253': [8364,-1,8218,402,8222,8230,8224,8225,-1,8240,-1,8249,-1,-1,-1,-1,-1,8216,8217,8220,8221,8226,8211,8212,-1,8482,-1,8250,-1,-1,-1,-1,160,901,902,163,164,165,166,167,168,169,-1,171,172,173,174,8213,176,177,178,179,900,181,182,183,904,905,906,187,908,189,910,911,912,913,914,915,916,917,918,919,920,921,922,923,924,925,926,927,928,929,-1,931,932,933,934,935,936,937,938,939,940,941,942,943,944,945,946,947,948,949,950,951,952,953,954,955,956,957,958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,973,974,-1],
  'Windows-1256': [8364,1662,8218,402,8222,8230,8224,8225,710,8240,1657,8249,338,1670,1688,1672,1711,8216,8217,8220,8221,8226,8211,8212,1705,8482,1681,8250,339,8204,8205,1722,160,1548,162,163,164,165,166,167,168,169,1726,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,1563,187,188,189,190,1567,1729,1569,1570,1571,1572,1573,1574,1575,1576,1577,1578,1579,1580,1581,1582,1583,1584,1585,1586,1587,1588,1589,1590,215,1591,1592,1593,1594,1600,1601,1602,1603,224,1604,226,1605,1606,1607,1608,231,232,233,234,235,1609,1610,238,239,1611,1612,1613,1614,244,1615,1616,247,1617,249,1618,251,252,8206,8207,1746],
  'KOI8-R': [9472,9474,9484,9488,9492,9496,9500,9508,9516,9524,9532,9600,9604,9608,9612,9616,9617,9618,9619,8992,9632,8729,8730,8776,8804,8805,160,8993,176,178,183,247,9552,9553,9554,1105,9555,9556,9557,9558,9559,9560,9561,9562,9563,9564,9565,9566,9567,9568,9569,1025,9570,9571,9572,9573,9574,9575,9576,9577,9578,9579,9580,169,1102,1072,1073,1094,1076,1077,1092,1075,1093,1080,1081,1082,1083,1084,1085,1086,1087,1103,1088,1089,1090,1091,1078,1074,1100,1099,1079,1096,1101,1097,1095,1098,1070,1040,1041,1062,1044,1045,1060,1043,1061,1048,1049,1050,1051,1052,1053,1054,1055,1071,1056,1057,1058,1059,1046,1042,1068,1067,1047,1064,1069,1065,1063,1066],
  'KOI8-U': [9472,9474,9484,9488,9492,9496,9500,9508,9516,9524,9532,9600,9604,9608,9612,9616,9617,9618,9619,8992,9632,8729,8730,8776,8804,8805,160,8993,176,178,183,247,9552,9553,9554,1105,1108,9556,1110,1111,9559,9560,9561,9562,9563,1169,9565,9566,9567,9568,9569,1025,1028,9571,1030,1031,9574,9575,9576,9577,9578,1168,9580,169,1102,1072,1073,1094,1076,1077,1092,1075,1093,1080,1081,1082,1083,1084,1085,1086,1087,1103,1088,1089,1090,1091,1078,1074,1100,1099,1079,1096,1101,1097,1095,1098,1070,1040,1041,1062,1044,1045,1060,1043,1061,1048,1049,1050,1051,1052,1053,1054,1055,1071,1056,1057,1058,1059,1046,1042,1068,1067,1047,1064,1069,1065,1063,1066],
  'CP437': [199,252,233,226,228,224,229,231,234,235,232,239,238,236,196,197,201,230,198,244,246,242,251,249,255,214,220,162,163,165,8359,402,225,237,243,250,241,209,170,186,191,8976,172,189,188,161,171,187,9617,9618,9619,9474,9508,9569,9570,9558,9557,9571,9553,9559,9565,9564,9563,9488,9492,9524,9516,9500,9472,9532,9566,9567,9562,9556,9577,9574,9568,9552,9580,9575,9576,9572,9573,9561,9560,9554,9555,9579,9578,9496,9484,9608,9604,9612,9616,9600,945,223,915,960,931,963,181,964,934,920,937,948,8734,966,949,8745,8801,177,8805,8804,8992,8993,247,8776,176,8729,183,8730,8319,178,9632,160],
  'CP850': [199,252,233,226,228,224,229,231,234,235,232,239,238,236,196,197,201,230,198,244,246,242,251,249,255,214,220,248,163,216,215,402,225,237,243,250,241,209,170,186,191,174,172,189,188,161,171,187,9617,9618,9619,9474,9508,193,194,192,169,9571,9553,9559,9565,162,165,9488,9492,9524,9516,9500,9472,9532,227,195,9562,9556,9577,9574,9568,9552,9580,164,240,208,202,203,200,305,205,206,207,9496,9484,9608,9604,166,204,9600,211,223,212,210,245,213,181,254,222,218,219,217,253,221,175,180,173,177,8215,190,182,167,247,184,176,168,183,185,179,178,9632,160],
  'CP866': [1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,9617,9618,9619,9474,9508,9569,9570,9558,9557,9571,9553,9559,9565,9564,9563,9488,9492,9524,9516,9500,9472,9532,9566,9567,9562,9556,9577,9574,9568,9552,9580,9575,9576,9572,9573,9561,9560,9554,9555,9579,9578,9496,9484,9608,9604,9612,9616,9600,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1101,1102,1103,1025,1105,1028,1108,1031,1111,1038,1118,176,8729,183,8730,8470,164,9632,160],
  'MacRoman': [196,197,199,201,209,214,220,225,224,226,228,227,229,231,233,232,234,235,237,236,238,239,241,243,242,244,246,245,250,249,251,252,8224,176,162,163,167,8226,182,223,174,169,8482,180,168,8800,198,216,8734,177,8804,8805,165,181,8706,8721,8719,960,8747,170,186,937,230,248,191,161,172,8730,402,8776,8710,171,187,8230,160,192,195,213,338,339,8211,8212,8220,8221,8216,8217,247,9674,255,376,8260,8364,8249,8250,64257,64258,8225,183,8218,8222,8240,194,202,193,203,200,205,206,207,204,211,212,63743,210,218,219,217,305,710,732,175,728,729,730,184,733,731,711],
};

// IBM EBCDIC sets: not ASCII-compatible at all, so the full 0x00-0xFF -> code point table is needed.
const FULL = {
  'IBM EBCDIC (CP037)': [0,1,2,3,156,9,134,127,151,141,142,11,12,13,14,15,16,17,18,19,157,133,8,135,24,25,146,143,28,29,30,31,128,129,130,131,132,10,23,27,136,137,138,139,140,5,6,7,144,145,22,147,148,149,150,4,152,153,154,155,20,21,158,26,32,160,226,228,224,225,227,229,231,241,162,46,60,40,43,124,38,233,234,235,232,237,238,239,236,223,33,36,42,41,59,172,45,47,194,196,192,193,195,197,199,209,166,44,37,95,62,63,248,201,202,203,200,205,206,207,204,96,58,35,64,39,61,34,216,97,98,99,100,101,102,103,104,105,171,187,240,253,254,177,176,106,107,108,109,110,111,112,113,114,170,186,230,184,198,164,181,126,115,116,117,118,119,120,121,122,161,191,208,221,222,174,94,163,165,183,169,167,182,188,189,190,91,93,175,168,180,215,123,65,66,67,68,69,70,71,72,73,173,244,246,242,243,245,125,74,75,76,77,78,79,80,81,82,185,251,252,249,250,255,92,247,83,84,85,86,87,88,89,90,178,212,214,210,211,213,48,49,50,51,52,53,54,55,56,57,179,219,220,217,218,159],
  'IBM EBCDIC (CP500)': [0,1,2,3,156,9,134,127,151,141,142,11,12,13,14,15,16,17,18,19,157,133,8,135,24,25,146,143,28,29,30,31,128,129,130,131,132,10,23,27,136,137,138,139,140,5,6,7,144,145,22,147,148,149,150,4,152,153,154,155,20,21,158,26,32,160,226,228,224,225,227,229,231,241,91,46,60,40,43,33,38,233,234,235,232,237,238,239,236,223,93,36,42,41,59,94,45,47,194,196,192,193,195,197,199,209,166,44,37,95,62,63,248,201,202,203,200,205,206,207,204,96,58,35,64,39,61,34,216,97,98,99,100,101,102,103,104,105,171,187,240,253,254,177,176,106,107,108,109,110,111,112,113,114,170,186,230,184,198,164,181,126,115,116,117,118,119,120,121,122,161,191,208,221,222,174,162,163,165,183,169,167,182,188,189,190,172,124,175,168,180,215,123,65,66,67,68,69,70,71,72,73,173,244,246,242,243,245,125,74,75,76,77,78,79,80,81,82,185,251,252,249,250,255,92,247,83,84,85,86,87,88,89,90,178,212,214,210,211,213,48,49,50,51,52,53,54,55,56,57,179,219,220,217,218,159],
};

// Multi-byte CJK sets: TextDecoder supports these labels natively, but TextEncoder only ever
// produces UTF-8, so there is no native way to encode *into* them. The reverse (char -> bytes) map
// is instead built lazily by brute-forcing every 1- and 2-byte sequence through TextDecoder once
// and caching the result; this covers the 1/2-byte repertoire of each set (GB18030's 4-byte
// supplementary-plane extension is not covered - those rare characters fall back like any other
// unmappable character).
const CJK_LABEL = { Shift_JIS: 'shift_jis', 'EUC-JP': 'euc-jp', GBK: 'gbk', GB18030: 'gb18030', Big5: 'big5', 'EUC-KR': 'euc-kr' };

const reverseMapCache = new Map();
function cjkReverseMap(label) {
  if (reverseMapCache.has(label)) return reverseMapCache.get(label);
  const dec = new TextDecoder(label, { fatal: true });
  const map = new Map();
  for (let b = 0; b < 256; b++) {
    try { const s = dec.decode(Uint8Array.of(b)); if ([...s].length === 1) map.set(s, [b]); } catch { /* invalid byte */ }
  }
  for (let hi = 0; hi < 256; hi++) {
    for (let lo = 0; lo < 256; lo++) {
      try { const s = dec.decode(Uint8Array.of(hi, lo)); if ([...s].length === 1 && !map.has(s)) map.set(s, [hi, lo]); } catch { /* invalid pair */ }
    }
  }
  reverseMapCache.set(label, map);
  return map;
}

// ISO-2022-JP is stateful (ESC sequences switch between ASCII and JIS X 0208), so its reverse map
// is built by wrapping every JIS X 0208 code pair in the switch-in/switch-out escapes and decoding.
let jisMapCache = null;
function jis0208ReverseMap() {
  if (jisMapCache) return jisMapCache;
  const dec = new TextDecoder('iso-2022-jp', { fatal: true });
  const map = new Map();
  for (let hi = 0x21; hi <= 0x7e; hi++) {
    for (let lo = 0x21; lo <= 0x7e; lo++) {
      try {
        const s = dec.decode(Uint8Array.of(0x1b, 0x24, 0x42, hi, lo, 0x1b, 0x28, 0x42));
        if ([...s].length === 1) map.set(s, [hi, lo]);
      } catch { /* unassigned pair */ }
    }
  }
  jisMapCache = map;
  return map;
}

const singleByteReverseCache = new Map();
function singleByteLookup(name) {
  let map = singleByteReverseCache.get(name);
  if (!map) {
    map = new Map();
    HI[name].forEach((cp, i) => { if (cp >= 0 && !map.has(cp)) map.set(cp, 128 + i); });
    singleByteReverseCache.set(name, map);
  }
  return cp => (cp < 128 ? [cp] : (map.has(cp) ? [map.get(cp)] : undefined));
}

const fullByteReverseCache = new Map();
function fullByteLookup(name) {
  let map = fullByteReverseCache.get(name);
  if (!map) {
    map = new Map();
    FULL[name].forEach((cp, byte) => { if (cp >= 0 && !map.has(cp)) map.set(cp, byte); });
    fullByteReverseCache.set(name, map);
  }
  return cp => (map.has(cp) ? [map.get(cp)] : undefined);
}

function cjkLookup(label) {
  const map = cjkReverseMap(label);
  return cp => map.get(String.fromCodePoint(cp));
}

function asciiLookup(cp) { return cp < 128 ? [cp] : undefined; }
function latin1Lookup(cp) { return cp < 256 ? [cp] : undefined; }

// Shared "errors=replace" semantics: an unmappable character becomes '?', re-looked-up through the
// same table (so e.g. EBCDIC gets its own byte for '?', not ASCII's 0x3F) - matching Python's
// codecs.replace_errors for encoding. In strict mode (used by the brute-force op's "Encode" mode)
// it throws instead, mirroring Python's UnicodeEncodeError.
function encodeWithLookup(text, lookup, strict) {
  const qBytes = lookup(0x3f);
  const out = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    let bytes = lookup(cp);
    if (bytes === undefined) {
      if (strict) throw new Error('UnicodeEncodeError');
      bytes = qBytes || [0x3f];
    }
    out.push(...bytes);
  }
  return new Uint8Array(out);
}

function decodeWithTable(data, table, asciiCompatible) {
  let out = '';
  for (const b of data) {
    const cp = asciiCompatible && b < 128 ? b : table[asciiCompatible ? b - 128 : b];
    out += String.fromCodePoint(cp < 0 ? 0xfffd : cp);
  }
  return out;
}

function encodeUtf16Bytes(text, be) {
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    if (be) { out[i * 2] = cc >> 8; out[i * 2 + 1] = cc & 0xff; }
    else { out[i * 2] = cc & 0xff; out[i * 2 + 1] = cc >> 8; }
  }
  return out;
}

function encodeUtf32Bytes(text, be) {
  const cps = [...text];
  const out = new Uint8Array(cps.length * 4);
  cps.forEach((ch, i) => {
    const cp = ch.codePointAt(0);
    const bytes = [(cp >>> 24) & 0xff, (cp >>> 16) & 0xff, (cp >>> 8) & 0xff, cp & 0xff];
    out.set(be ? bytes : bytes.reverse(), i * 4);
  });
  return out;
}

function decodeUtf32Bytes(data, be) {
  let out = '';
  const n = data.length - (data.length % 4);
  for (let i = 0; i < n; i += 4) {
    const cp = be
      ? data[i] * 0x1000000 + data[i + 1] * 0x10000 + data[i + 2] * 0x100 + data[i + 3]
      : data[i + 3] * 0x1000000 + data[i + 2] * 0x10000 + data[i + 1] * 0x100 + data[i];
    out += (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) ? '�' : String.fromCodePoint(cp);
  }
  if (data.length % 4) out += '�';
  return out;
}

function decodeUtf16Auto(data) {
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) return new TextDecoder('utf-16le').decode(data.subarray(2));
  if (data.length >= 2 && data[0] === 0xfe && data[1] === 0xff) return new TextDecoder('utf-16be').decode(data.subarray(2));
  return new TextDecoder('utf-16le').decode(data);
}

// UTF-7 (RFC 2152): printable ASCII except '+', '\\' and '~' is written literally; everything else
// runs through modified base64 of its UTF-16BE bytes, bracketed by '+' ... '-'. A lone '+' is
// shorthanded as "+-"; the closing '-' is only required when omitting it would be ambiguous (end of
// string, or the following literal character is itself '-' or part of the base64 alphabet).
const UTF7_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function isUtf7Direct(cc) {
  return cc === 9 || cc === 10 || cc === 13 || (cc >= 0x20 && cc <= 0x7e && cc !== 0x2b && cc !== 0x5c && cc !== 0x7e);
}
function utf7NeedsDash(cc) {
  return cc === 0x2d || (cc >= 0x30 && cc <= 0x39) || (cc >= 0x41 && cc <= 0x5a) || (cc >= 0x61 && cc <= 0x7a) || cc === 0x2f;
}
function encodeUtf7(text) {
  const out = [];
  let bitBuf = 0, bitCount = 0, inShift = false;
  const closeShift = dash => {
    if (bitCount > 0) { out.push(UTF7_B64.charCodeAt((bitBuf << (6 - bitCount)) & 0x3f)); bitBuf = 0; bitCount = 0; }
    if (dash) out.push(0x2d);
    inShift = false;
  };
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    if (isUtf7Direct(cc)) {
      if (inShift) closeShift(utf7NeedsDash(cc));
      out.push(cc);
      continue;
    }
    if (!inShift && cc === 0x2b) { out.push(0x2b, 0x2d); continue; }
    if (!inShift) { out.push(0x2b); inShift = true; }
    bitBuf = (bitBuf << 16) | cc;
    bitCount += 16;
    while (bitCount >= 6) { bitCount -= 6; out.push(UTF7_B64.charCodeAt((bitBuf >> bitCount) & 0x3f)); }
    bitBuf &= (1 << bitCount) - 1;
  }
  if (inShift) closeShift(true);
  return new Uint8Array(out);
}
function decodeUtf7(data) {
  const s = decodeLatin1(data);
  let out = '', i = 0;
  while (i < s.length) {
    if (s[i] !== '+') { out += s[i]; i++; continue; }
    i++;
    if (s[i] === '-') { out += '+'; i++; continue; }
    let bitBuf = 0, bitCount = 0;
    while (i < s.length && UTF7_B64.indexOf(s[i]) >= 0) {
      bitBuf = (bitBuf << 6) | UTF7_B64.indexOf(s[i]);
      bitCount += 6;
      i++;
      if (bitCount >= 16) { bitCount -= 16; out += String.fromCharCode((bitBuf >> bitCount) & 0xffff); }
    }
    if (s[i] === '-') i++;
  }
  return out;
}

function encodeIso2022Jp(text, strict) {
  const map = jis0208ReverseMap();
  const ESC_ASCII = [0x1b, 0x28, 0x42], ESC_JIS = [0x1b, 0x24, 0x42];
  const out = [];
  let mode = 'ascii';
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp < 128) {
      if (mode !== 'ascii') { out.push(...ESC_ASCII); mode = 'ascii'; }
      out.push(cp);
      continue;
    }
    const bytes = map.get(ch);
    if (bytes) {
      if (mode !== 'jis') { out.push(...ESC_JIS); mode = 'jis'; }
      out.push(...bytes);
    } else if (strict) {
      throw new Error('UnicodeEncodeError');
    } else {
      if (mode !== 'ascii') { out.push(...ESC_ASCII); mode = 'ascii'; }
      out.push(0x3f);
    }
  }
  if (mode !== 'ascii') out.push(...ESC_ASCII);
  return new Uint8Array(out);
}

export function decodeBytes(data, name) {
  switch (name) {
    case 'UTF-8': return decodeUtf8(data);
    case 'UTF-16LE': return new TextDecoder('utf-16le').decode(data);
    case 'UTF-16BE': return new TextDecoder('utf-16be').decode(data);
    case 'UTF-16': return decodeUtf16Auto(data);
    case 'UTF-32LE': return decodeUtf32Bytes(data, false);
    case 'UTF-32BE': return decodeUtf32Bytes(data, true);
    case 'UTF-7': return decodeUtf7(data);
    case 'ASCII': return decodeWithTable(data, new Array(128).fill(-1), true);
    case 'ISO-8859-1 (Latin1)': return decodeLatin1(data);
    case 'IBM EBCDIC (CP037)': case 'IBM EBCDIC (CP500)': return decodeWithTable(data, FULL[name], false);
    case 'Shift_JIS': case 'EUC-JP': case 'ISO-2022-JP': case 'GBK': case 'GB18030': case 'Big5': case 'EUC-KR':
      return new TextDecoder(name === 'ISO-2022-JP' ? 'iso-2022-jp' : CJK_LABEL[name], { fatal: false }).decode(data);
    default: return decodeWithTable(data, HI[name], true);
  }
}

export function encodeText(text, name, strict = false) {
  switch (name) {
    case 'UTF-8': return encodeUtf8(text);
    case 'UTF-16LE': return encodeUtf16Bytes(text, false);
    case 'UTF-16BE': return encodeUtf16Bytes(text, true);
    case 'UTF-16': { const body = encodeUtf16Bytes(text, false); const out = new Uint8Array(body.length + 2); out[0] = 0xff; out[1] = 0xfe; out.set(body, 2); return out; }
    case 'UTF-32LE': return encodeUtf32Bytes(text, false);
    case 'UTF-32BE': return encodeUtf32Bytes(text, true);
    case 'UTF-7': return encodeUtf7(text);
    case 'ASCII': return encodeWithLookup(text, asciiLookup, strict);
    case 'ISO-8859-1 (Latin1)': return encodeWithLookup(text, latin1Lookup, strict);
    case 'IBM EBCDIC (CP037)': case 'IBM EBCDIC (CP500)': return encodeWithLookup(text, fullByteLookup(name), strict);
    case 'Shift_JIS': case 'EUC-JP': case 'GBK': case 'GB18030': case 'Big5': case 'EUC-KR': return encodeWithLookup(text, cjkLookup(CJK_LABEL[name]), strict);
    case 'ISO-2022-JP': return encodeIso2022Jp(text, strict);
    default: return encodeWithLookup(text, singleByteLookup(name), strict);
  }
}

module('Encode text', 'Converts text (UTF-8 input) to bytes in another character encoding.', [A.select('Encoding', ENCODINGS)],
  (t, enc) => encodeText(t, enc, false), { text: true });
