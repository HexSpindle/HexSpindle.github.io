// SPDX-License-Identifier: MIT
// Validate optional downloaded IPinfo Lite database using HexSpindle's own MMDB parser.
import fs from 'node:fs/promises';
import { MmdbReader } from '../modules/networking/_mmdb.js';
const path=process.argv[2];
if(!path)throw new Error('Expected MMDB path');
const db=new MmdbReader(new Uint8Array(await fs.readFile(path)));
if(!db.metadata.databaseType || ![4,6].includes(db.metadata.ipVersion))
  throw new Error('Missing or unsupported MMDB metadata');
const probe=db.get('8.8.8.8');
if(!probe || typeof probe!=='object' || !(probe.asn || probe.country || probe.country_code))
  throw new Error('IPinfo Lite sample record missing country/ASN structure');
console.log(`PASS IPinfo Lite MMDB parser: ${db.metadata.databaseType} / IPv${db.metadata.ipVersion}`);
