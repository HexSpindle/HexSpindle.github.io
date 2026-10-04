import { module } from './_cat.js';

module('To COBS', 'Consistent Overhead Byte Stuffing: removes zero bytes from the data by replacing runs between them with length markers, for use on framed serial links.', [],
  (data) => {
    const out = [];
    let i = 0;
    while (true) {
      const chunkStart = i;
      while (i < data.length && data[i] !== 0 && i - chunkStart < 254) i++;
      out.push(i - chunkStart + 1);
      for (let j = chunkStart; j < i; j++) out.push(data[j]);
      if (i < data.length && data[i] === 0) i++;
      else if (i >= data.length) break;
    }
    out.push(0);
    return new Uint8Array(out);
  });
