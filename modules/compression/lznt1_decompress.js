import { module } from './_cat.js';

// LZNT1 (Microsoft's NTFS/registry-hive compression format, documented in [MS-XCA] section
// 2.3). Decompress-only, matching CyberChef's op (which also offers no compress side).
//
// Ported from CyberChef's src/core/lib/LZNT1.mjs (itself credited there to
// https://github.com/Velocidex/go-ntfs/blob/master/parser/lznt1.go), and verified against
// CyberChef's own test vector: the bytes "\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot"
// decompress to "compressedtestdatacompressedalot".
//
// A compressed stream is a sequence of 4KB-chunk "blocks", each starting with a little-endian
// 16-bit header: bit 15 set means the block body is compressed, bits 0-11 hold (body length - 1)
// in bytes, a header of 0 ends the stream. An uncompressed block's body is copied verbatim. A
// compressed block's body is a sequence of 8-flag-bit groups: a clear bit is a literal byte, a
// set bit is a 2-byte little-endian (offset, length) back-reference whose split point depends on
// how far into the *current 4KB block's output* the reference sits (more output so far means
// fewer bits are spent on the length and more on the offset).
const COMPRESSED_MASK = 1 << 15;
const SIZE_MASK = (1 << 12) - 1;

function getDisplacement(offset) {
  let result = 0;
  while (offset >= 0x10) { offset >>= 1; result += 1; }
  return result;
}

module('LZNT1 Decompress', "Decompresses data using Microsoft's LZNT1 algorithm (NTFS compressed files, registry hives). Similar to the Windows API RtlDecompressBuffer.", [],
  (compressed) => {
    const decompressed = [];
    let coffset = 0;

    while (coffset + 2 <= compressed.length) {
      const doffset = decompressed.length;

      const blockHeader = compressed[coffset] | (compressed[coffset + 1] << 8);
      coffset += 2;

      const size = blockHeader & SIZE_MASK;
      const blockEnd = coffset + size + 1;

      if (size === 0) {
        break;
      } else if (compressed.length < coffset + size) {
        throw new Error('Malformed LZNT1 stream: Block too small! Has the stream been truncated?');
      }

      if ((blockHeader & COMPRESSED_MASK) !== 0) {
        while (coffset < blockEnd) {
          let header = compressed[coffset++];

          for (let i = 0; i < 8 && coffset < blockEnd; i++) {
            if ((header & 1) === 0) {
              decompressed.push(compressed[coffset++]);
            } else {
              const pointer = compressed[coffset] | (compressed[coffset + 1] << 8);
              coffset += 2;

              const displacement = getDisplacement(decompressed.length - doffset - 1);
              const symbolOffset = (pointer >> (12 - displacement)) + 1;
              const symbolLength = (pointer & (0xFFF >> displacement)) + 2;
              const shiftOffset = decompressed.length - symbolOffset;

              for (let shiftDelta = 0; shiftDelta < symbolLength + 1; shiftDelta++) {
                const shift = shiftOffset + shiftDelta;
                if (shift < 0 || decompressed.length <= shift) {
                  throw new Error('Malformed LZNT1 stream: Invalid shift!');
                }
                decompressed.push(decompressed[shift]);
              }
            }
            header >>= 1;
          }
        }
      } else {
        for (let k = coffset; k < coffset + size + 1; k++) decompressed.push(compressed[k]);
        coffset += size + 1;
      }
    }

    return Uint8Array.from(decompressed);
  });
