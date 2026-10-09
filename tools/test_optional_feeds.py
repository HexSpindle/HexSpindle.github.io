#!/usr/bin/env python3
"""Isolated tests for abuse.ch exports; never contact network providers."""
import gzip,hashlib,io,json,pathlib,tempfile,unittest,zipfile,tarfile
from unittest.mock import patch
from sync_abusech_feeds import publish, csv_rows, normalize
from sync_enrichment_feeds import write_manifest, sync_maxmind_optional
from sync_geolite_city import (process as city_process, carry_forward as city_carry,
                               fetch_archive, _MaxMindSafeRedirect, DATASET as CITY_ID, URL)
import urllib.error
import urllib.request
import datetime as dt

class OptionalFeedTests(unittest.TestCase):
    def test_maxmind_redirect_does_not_forward_authorization(self):
        auth='Basic DO-NOT-LEAK'
        req=urllib.request.Request(URL,headers={'Authorization':auth,'User-Agent':'HexSpindle'})
        target=('https://mm-prod-geoip-databases.'
                'a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com/'
                'signed-file?secret-signed-url=never-print')
        redirected=_MaxMindSafeRedirect().redirect_request(req,None,302,'Found',{},target)
        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header('Authorization'))
        self.assertEqual(req.get_header('Authorization'),auth)
        with self.assertRaisesRegex(RuntimeError,'unexpected destination'):
            _MaxMindSafeRedirect().redirect_request(req,None,302,'Found',{},
                'https://untrusted.example/leak')
        with self.assertRaisesRegex(RuntimeError,'unexpected destination'):
            _MaxMindSafeRedirect().redirect_request(req,None,302,'Found',{},
                'http://download.maxmind.com/insecure')

    def test_maxmind_http_status_diagnostic_has_no_credentials(self):
        class FailedOpener:
            def __init__(self,code):self.code=code
            def open(self,request,timeout):
                raise urllib.error.HTTPError('https://private.example/signed-very-secret',
                    self.code,'failure',{},None)
        for code,label in [(401,'authentication'),(403,'access denied'),(429,'rate limit'),(503,'service')]:
            with self.subTest(status=code):
                with patch('sync_geolite_city.urllib.request.build_opener',return_value=FailedOpener(code)):
                    with self.assertRaises(RuntimeError) as failure:
                        fetch_archive('123456','NEVER-SHOW-THIS-KEY')
                self.assertIn('HTTP '+str(code),str(failure.exception))
                self.assertIn(label,str(failure.exception))
                self.assertNotIn('NEVER-SHOW-THIS-KEY',str(failure.exception))
                self.assertNotIn('signed-very-secret',str(failure.exception))

    def test_maxmind_failure_does_not_block_publishing(self):
        def unavailable(*_):raise RuntimeError('MaxMind HTTP 401: authentication failed')
        with tempfile.TemporaryDirectory() as td:
            dest=pathlib.Path(td)
            info,reason=sync_maxmind_optional(dest,True,False,'account','license',
                process_func=unavailable,previous_loader=lambda:self.fail('Do not fetch prior if disabled'))
            self.assertIsNone(info)
            self.assertIn('disabled',reason)
            self.assertEqual(list(dest.iterdir()),[])
            recent=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=3)).isoformat()
            previous={'database_build_at':recent,'database_updated_date':recent[:10]}
            calls=[]
            def restored(_,data):
                calls.append(data)
                return {'sha256':'valid-mock-sha','database_updated_date':data['database_updated_date']}
            info,reason=sync_maxmind_optional(dest,True,True,'account','license',
                process_func=unavailable,previous_loader=lambda:previous,carry_func=restored)
            self.assertIsNone(reason)
            self.assertEqual(info['sha256'],'valid-mock-sha')
            self.assertEqual(len(calls),1)
            info,reason=sync_maxmind_optional(dest,True,True,'account','license',
                process_func=unavailable,previous_loader=lambda:None)
            self.assertIsNone(info)
            self.assertIn('HTTP 401',reason)
            old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=40)).isoformat()
            info,reason=sync_maxmind_optional(dest,False,True,'account','license',
                previous_loader=lambda:{'database_build_at':old},
                carry_func=lambda *_:self.fail('Must not publish stale MaxMind data'))
            self.assertIsNone(info)
            self.assertIn('not currently published',reason)

    def test_maxmind_verify_only_publish_and_carry_forward(self):
        # Synthetic archive; never downloads provider data or needs credentials.
        raw=b'A'*(5_200_000-32)+b'\xab\xcd\xefMaxMind.com'+b'\x00'*19
        epoch=1791072000
        meta={'database_type':'GeoLite2-City','build_epoch':epoch,'mmdb_format_version':'2.0','ip_version':6}
        archive_io=io.BytesIO()
        with tarfile.open(fileobj=archive_io,mode='w:gz') as tf:
            entry=tarfile.TarInfo('GeoLite2-City_TEST/GeoLite2-City.mmdb')
            entry.size=len(raw)
            tf.addfile(entry,io.BytesIO(raw))
        calls=[]
        def fake_fetch(account,key):
            calls.append((account,key))
            return archive_io.getvalue(), 'Fri, 09 Oct 2026 00:00:00 GMT'
        def fake_inspector(_):return meta
        with tempfile.TemporaryDirectory() as td:
            output=pathlib.Path(td)
            result,check=city_process('acct','secret',False,output,fake_fetch,fake_inspector)
            self.assertIsNone(result)
            self.assertEqual(check['status'],'verified_not_saved')
            self.assertEqual(list(output.iterdir()),[])
            result,check=city_process('acct','secret',True,output,fake_fetch,fake_inspector)
            self.assertEqual(result['database_name'],'GeoLite2-City.mmdb')
            self.assertIn('database_updated_date',result)
            self.assertIn(CITY_ID,{'maxmind_geolite2_city':result})
            source=output/'geolite2-city.mmdb.gz'
            self.assertEqual(gzip.decompress(source.read_bytes()),raw)
            with tempfile.TemporaryDirectory() as next_td:
                restored=city_carry(pathlib.Path(next_td),result,fetcher=lambda _:source.read_bytes(),inspector=fake_inspector)
                self.assertEqual(restored['sha256'],result['sha256'])
                self.assertEqual((pathlib.Path(next_td)/source.name).read_bytes(),source.read_bytes())
            self.assertEqual(len(calls),2)

    def test_maxmind_absent_secrets_do_not_download(self):
        with tempfile.TemporaryDirectory() as td:
            result,status=city_process('','',False,pathlib.Path(td),archive_loader=lambda *_:self.fail('Unexpected download'))
            self.assertIsNone(result)
            self.assertEqual(status['status'],'missing_secrets')
            self.assertEqual(list(pathlib.Path(td).iterdir()),[])

    def test_manifest_distinguishes_unpublished_from_synced(self):
        with tempfile.TemporaryDirectory() as td:
            target=pathlib.Path(td)
            reason='Public redistribution not authorized'
            write_manifest(target, {'sans_intelfeed': {'path':'data/feeds/test.gz'}},
                           {'abusech_threatfox':reason,'abusech_urlhaus':reason})
            manifest=json.loads((target/'manifest.json').read_text())
            self.assertEqual(manifest['schema_version'],1)
            self.assertNotIn('abusech_threatfox',manifest['datasets'])
            self.assertEqual(manifest['unavailable']['abusech_urlhaus'],reason)

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

if __name__=='__main__':unittest.main()
