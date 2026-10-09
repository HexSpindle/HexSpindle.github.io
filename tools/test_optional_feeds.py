#!/usr/bin/env python3
"""Isolated tests; never contact MaxMind or abuse.ch."""
import gzip,hashlib,io,json,pathlib,tarfile,tempfile,unittest,zipfile
from sync_abusech_feeds import publish, csv_rows, normalize
from sync_private_maxmind import refresh

class OptionalFeedTests(unittest.TestCase):
    def test_permission_gate_and_exports(self):
        raw_threat=b'# ThreatFox export\nioc,ioc_type,threat_type,malware_printable,confidence_level\n198.51.100.7:443,ip:port,botnet_cc,FakeExample,75\n'
        contents=io.BytesIO()
        with zipfile.ZipFile(contents,'w') as zip:zip.writestr('full.csv',raw_threat)
        url_csv=b'id,dateadded,url,url_status\n42,2026-10-09,https://bad.example/Malware,online\n'
        calls=[]
        def fake_get(url):
            calls.append(url)
            return (contents.getvalue() if 'threatfox' in url else url_csv),'Fri, 09 Oct 2026 05:00:00 GMT'
        with tempfile.TemporaryDirectory() as td:
            output=pathlib.Path(td)
            self.assertEqual(publish(output,'TOPSECRET',False,fake_get),{})
            self.assertEqual(calls,[],'Must not call provider without permission')
            info=publish(output,'TOPSECRET',True,fake_get)
            self.assertEqual(set(info),{'abusech_threatfox','abusech_urlhaus'})
            for name in info:
                path=output/pathlib.Path(info[name]['path']).name
                self.assertTrue(path.is_file())
                raw=gzip.decompress(path.read_bytes())
                self.assertEqual(hashlib.sha256(raw).hexdigest(),info[name]['sha256'])
                self.assertNotIn('TOPSECRET',json.dumps(info))
                self.assertEqual(info[name]['records'],1)
                self.assertIn('indicator',json.loads(raw))
            self.assertEqual(len(calls),2)

    def test_threatfox_quoted_csv_header_and_fields(self):
        # Reproduces the real export format: comments, quoted commented header,
        # and whitespace between commas and the opening field quotes.
        threat = (
            b'# ThreatFox IOCs: additions - CSV format (full dump)\n'
            b'# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"\n'
            b'"2026-10-09 04:31:23", "12", "https://malicious.example/Path", "url", "botnet_cc", "example", "None", "Example", "2026-10-09 05:30:00", "75", "False", "None", "x", "0", "tester"\n'
            b'# Number of entries: 1\n'
        )
        container = io.BytesIO()
        with zipfile.ZipFile(container, 'w') as archive:
            archive.writestr('full.csv', threat)
        rows=list(csv_rows(container.getvalue()))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['first_seen_utc'], '2026-10-09 04:31:23')
        self.assertEqual(rows[0]['ioc_value'], 'https://malicious.example/Path')
        self.assertEqual(rows[0]['ioc_type'], 'url')
        self.assertEqual(rows[0]['confidence_level'], '75')
        item=normalize('abusech_threatfox', rows[0])
        self.assertEqual(item['indicator'], 'https://malicious.example/Path')
        self.assertEqual(item['first_seen'], '2026-10-09 04:31:23')
        self.assertEqual(item['last_seen'], '2026-10-09 05:30:00')
        self.assertEqual(item['confidence'], '75')
        with tempfile.TemporaryDirectory() as td:
            def fake_get(url):
                if 'threatfox' in url: return container.getvalue(), None
                return b'# id,dateadded,url,url_status\n"1","2026-10-09","https://bad.example/Path","online"\n', None
            info=publish(pathlib.Path(td), 'DUMMY', True, fake_get)
            self.assertIn('historical', info['abusech_threatfox']['scope'])
            payload=gzip.decompress((pathlib.Path(td)/'abusech-threatfox-iocs.jsonl.gz').read_bytes())
            stored=json.loads(payload)
            self.assertEqual(stored['indicator'], 'https://malicious.example/Path')
            self.assertEqual(stored['first_seen'], '2026-10-09 04:31:23')

    def test_maxmind_private_only(self):
        # synthetic MMDB marker in valid TAR container; validates archive semantics
        payload=b'X'*(200*1024)+b'\xab\xcd\xefMaxMind.com'+b'Y'*32
        tarbytes=io.BytesIO()
        with tarfile.open(fileobj=tarbytes,mode='w:gz') as f:
            name='GeoLite2-City_20261009/GeoLite2-City.mmdb'
            member=tarfile.TarInfo(name);member.size=len(payload)
            f.addfile(member,io.BytesIO(payload))
        called=[]
        def upload(path,bucket,digest):
            self.assertEqual(path.read_bytes(),payload)
            called.append((bucket,digest))
        self.assertEqual(refresh('','')['status'],'skipped')
        report=refresh('ACCT','FAKE',downloader=lambda:tarbytes.getvalue())
        self.assertEqual(report['status'],'verified_not_retained')
        report=refresh('ACCT','FAKE','private-bucket',downloader=lambda:tarbytes.getvalue(),uploader=upload)
        self.assertEqual(report['status'],'stored_in_private_s3')
        self.assertEqual(len(called),1)
        self.assertEqual(called[0][1],hashlib.sha256(payload).hexdigest())
        with self.assertRaisesRegex(ValueError,'archive'):
            refresh('ACCT','FAKE',downloader=lambda:b'garbage')

if __name__=='__main__':unittest.main()
