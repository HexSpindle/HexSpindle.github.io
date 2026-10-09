// SPDX-License-Identifier: MIT
// Validate the actual MMDB metadata; the filename and tar directory are untrusted.
import { readFileSync } from 'node:fs';
import { inspectMmdb } from '../modules/networking/_mmdb.js';
const filename = process.argv[2];
if (!filename) throw new Error('Missing MMDB filename');
const m = inspectMmdb(readFileSync(filename));
if (m.databaseType !== 'GeoLite2-City') throw new Error('Expected GeoLite2-City MMDB, got '+m.databaseType);
if (!Number.isFinite(m.buildEpoch) || m.buildEpoch < 1451606400 || m.buildEpoch > Date.now()/1000+86400)
  throw new Error('Invalid MMDB build epoch');
console.log(JSON.stringify({database_type:m.databaseType,build_epoch:m.buildEpoch,
  mmdb_format_version:`${m.binaryFormatMajorVersion}.${m.binaryFormatMinorVersion}`,
  ip_version:m.ipVersion}));
