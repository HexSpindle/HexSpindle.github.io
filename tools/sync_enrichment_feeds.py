#!/usr/bin/env python3
"""Build same-origin feed snapshots for HexSpindle Pages. Python stdlib only.

SANS feeds: https://isc.sans.edu/feeds_doc.html (attribution required; no resale).
RIR delegations: RIR/NRO public extended delegated stats (NOT Bulk Whois).
"""
from __future__ import annotations
import argparse, datetime as dt, gzip, hashlib, io, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.error, urllib.request

UTC = dt.timezone.utc
NOW = lambda: dt.datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')
SANS = {
 'sans_intelfeed': ('https://isc.sans.edu/api/intelfeed?json', 'sans-intelfeed.json.gz', 1500),
 'sans_threatintel': ('https://isc.sans.edu/feeds/threatintel.txt', 'sans-threatintel.txt.gz', 5000),
 'sans_daily_sources': ('https://feeds.dshield.org/feeds/daily_sources', 'sans-daily-sources.tsv.gz', 100000),
}
RIRS = {
 'arin': 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
 'apnic': 'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
 'ripencc': 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
 'lacnic': 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
 'afrinic': 'https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest',
}
IANA = {
 'iana_ipv4': ('https://data.iana.org/rdap/ipv4.json', 'iana-ipv4.json.gz'),
 'iana_ipv6': ('https://data.iana.org/rdap/ipv6.json', 'iana-ipv6.json.gz'),
}
HEADERS = {'User-Agent': 'HexSpindle-FeedSync/1.0 (+https://github.com/HexSpindle/HexSpindle)',
           'Accept-Encoding':'identity'}
MAX_BYTES = 250 * 1024 * 1024

def download(url: str, target: pathlib.Path, min_bytes=512):
    error = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(request, timeout=150) as resp, target.open('wb') as out:
                status = getattr(resp, 'status', 200)
                if status != 200: raise ValueError(f'HTTP {status}')
                length = resp.headers.get('Content-Length')
                if resp.headers.get('Content-Encoding', '').lower() not in ('', 'identity'):
                    raise ValueError('Unexpected compressed HTTP transport')
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk: break
                    size += len(chunk)
                    if size > MAX_BYTES: raise ValueError(f'Download over {MAX_BYTES} bytes')
                    out.write(chunk); digest.update(chunk)
                if size < min_bytes: raise ValueError(f'Too small: {size} bytes')
                if length is not None and size != int(length):
                    raise ValueError(f'Content-Length mismatch ({size} != {length})')
                return {'source_url':url, 'source_modified_at':resp.headers.get('Last-Modified'),
                        'source_etag':resp.headers.get('ETag'), 'raw_bytes':size, 'sha256':digest.hexdigest(),
                        'source_retrieved_at':NOW()}
        except Exception as exc:
            error = exc
            target.unlink(missing_ok=True)
            if attempt < 2: time.sleep(2 * (attempt+1))
    raise RuntimeError(f'Could not download requested feed after three attempts: {error}')

def publish_gzip(source: pathlib.Path, dest: pathlib.Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as s, dest.open('wb') as d:
        with gzip.GzipFile(filename='', mode='wb', fileobj=d, compresslevel=6, mtime=0) as gz:
            shutil.copyfileobj(s, gz, length=1024*1024)
    return dest.stat().st_size

def v4_token(s):
    try: return str(ipaddress.IPv4Address('.'.join(str(int(x)) for x in s.split('.'))))
    except (ValueError, TypeError): return None

def valid_ip_token(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError: return bool(v4_token(s))

def validate_sans(kind, path: pathlib.Path):
    # Verify more than HTTP 200: reject error pages and unexpected response shapes.
    if kind == 'sans_intelfeed':
        with path.open('r', encoding='utf-8') as f: data = json.load(f)
        if not isinstance(data, (dict, list)): raise ValueError('Unexpected IntelFeed root')
        return {'records': None, 'format': 'json', 'validation': 'json parsed'}
    matched, lines = 0, 0
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            lines += 1
            if not line.strip() or line.lstrip().startswith(('#',';','//')): continue
            if kind == 'sans_daily_sources':
                cols = line.split('\t')
                if len(cols) >= 7 and v4_token(cols[0].strip()): matched += 1
            else:
                parts = re.split(r'[\t,\s]+', line.strip(), maxsplit=4)
                if any(valid_ip_token(p) for p in parts[:3]): matched += 1
            if lines >= 10000: break
    threshold = 100 if kind == 'sans_daily_sources' else 5
    if matched < threshold: raise ValueError(f'Unexpected {kind} data shape: {matched}/{lines} sampled valid lines')
    return {'records': None, 'format': 'tsv' if kind == 'sans_daily_sources' else 'text',
            'validation': f'{matched}/{lines} sampled lines parsed'}

def parse_rir(path: pathlib.Path, name: str, out):
    count = 0; dates = []
    with path.open('r', encoding='ascii', errors='replace') as inp:
        for raw in inp:
            if raw.startswith('#') or '|' not in raw: continue
            cols = raw.rstrip('\r\n').split('|')
            if len(cols) < 7: continue
            rir, cc, kind, start, value, date, status = cols[:7]
            if rir.lower() not in (name, 'ripencc' if name=='ripencc' else name): continue
            if kind not in ('ipv4', 'ipv6') or status not in ('allocated','assigned'): continue
            try:
                ip = ipaddress.ip_address(start)
                if (kind=='ipv4' and ip.version!=4) or (kind=='ipv6' and ip.version!=6): continue
                amount = int(value)
                if amount <= 0 or (kind=='ipv6' and amount > 128) or (kind=='ipv4' and amount > 2**32): continue
                if kind=='ipv4' and int(ip) + amount > 2**32: continue
            except ValueError: continue
            # Normalize back to 7 fields; optional extended opaque columns are not exported.
            out.write('|'.join((name, cc, kind, start, value, date, status)) + '\n')
            count += 1
            if date and len(date)==8 and date.isdigit(): dates.append(date)
    if count < 200: raise ValueError(f'Invalid or empty {name} allocation file ({count} lines)')
    return {'records':count, 'latest_allocation_date': max(dates) if dates else None}

def md5_validate_arin(path: pathlib.Path, temp_dir: pathlib.Path):
    checksum = temp_dir / 'arin.md5'
    try:
        download(RIRS['arin'] + '.md5', checksum, min_bytes=32)
        content = checksum.read_text(errors='replace')
        expected = re.search(r'\b[a-f0-9]{32}\b', content, flags=re.I)
        if not expected: raise ValueError('No MD5 digest found')
        actual = hashlib.md5(path.read_bytes()).hexdigest()
        if actual.lower() != expected.group(0).lower(): raise ValueError('ARIN publisher MD5 mismatch')
        return actual
    except Exception as exc:
        # Do not silently accept checksum mismatches. Missing checksum is allowed, but surfaced.
        if 'mismatch' in str(exc): raise
        print(f'NOTICE: ARIN MD5 not verified: {exc}', file=sys.stderr)
        return None

def sync_ipinfo_lite(secret: str, temp: pathlib.Path, dest: pathlib.Path):
    """Only for explicitly configured free IPinfo Lite credentials, CC BY-SA 4.0.

    The token never appears in public artifacts, filenames or printed failure messages.
    """
    from urllib.parse import quote
    if not secret: return None
    safe_url = 'https://ipinfo.io/data/ipinfo_lite.mmdb'
    real_url = safe_url + '?token=' + quote(secret, safe='')
    source = temp / 'ipinfo_lite.mmdb'
    try:
        meta = download(real_url, source, min_bytes=20000)
        data = source.read_bytes()
        if b'\xab\xcd\xefMaxMind.com' not in data[-131100:]:
            raise ValueError('Invalid IPinfo Lite MMDB: metadata signature missing')
        verifier = pathlib.Path(__file__).with_name('validate_lite_mmdb.mjs')
        subprocess.run(['node', str(verifier), str(source)], check=True, capture_output=True, text=True, timeout=90)
        meta['source_url'] = safe_url
        meta['path'] = 'data/feeds/ipinfo-lite.mmdb.gz'
        meta['compressed_bytes'] = publish_gzip(source, dest / 'ipinfo-lite.mmdb.gz')
        meta['feed_type'] = 'ipinfo_lite'
        meta['license'] = 'CC BY-SA 4.0'
        meta['attribution'] = 'IPinfo Lite — https://ipinfo.io'
        return meta
    except Exception as exc:
        raise RuntimeError('Could not retrieve configured IPinfo Lite database: ' +
                           str(exc).replace(secret, '[REDACTED]')) from None

def write_manifest(output, datasets, unavailable=None):
    manifest = {'schema_version':1, 'generated_at':NOW(), 'attribution':{
      'sans': 'SANS Technology Institute, Internet Storm Center — https://isc.sans.edu',
      'rir': 'RIR extended delegation statistics, https://www.nro.net'}, 'datasets':datasets}
    if unavailable: manifest['unavailable'] = unavailable
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n', encoding='utf-8')

def reuse_live_snapshot(dest: pathlib.Path, base_url='https://hexspindle.github.io/'):
    """For code pushes, reuse already-public feeds without re-fetching SANS/RIR providers."""
    url=base_url.rstrip('/') + '/data/feeds/manifest.json'
    try:
        request=urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(request, timeout=60) as response:
            if getattr(response,'status',200)!=200: raise RuntimeError('Published manifest unavailable')
            manifest=json.load(response)
    except urllib.error.HTTPError as e:
        if e.code==404: return False  # first deployment; no previous snapshot
        raise
    if manifest.get('schema_version')!=1 or not isinstance(manifest.get('datasets'),dict):
        raise ValueError('Published manifest has an unexpected structure')
    for kind,info in manifest['datasets'].items():
        relative=info.get('path','')
        if not re.fullmatch(r'data/feeds/[a-z0-9_.-]+\.gz',relative):
            raise ValueError(f'Invalid published path: {relative}')
        source=base_url.rstrip('/')+'/'+relative
        path=dest/pathlib.Path(relative).name
        download(source,path,min_bytes=32)
        sha=hashlib.sha256();size=0
        with gzip.open(path,'rb') as gz:
            while True:
                chunk=gz.read(1024*1024)
                if not chunk:break
                sha.update(chunk);size+=len(chunk)
                if size>MAX_BYTES:raise ValueError('Snapshot exceeds size limit')
        if sha.hexdigest()!=info['sha256'] or size!=info['raw_bytes']:
            raise ValueError(f'{kind} published artifact does not match its manifest')
    (dest/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print('Reused verified currently-published snapshot. No SANS/RIR upstream requests.',flush=True)
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument('output')
    p.add_argument('--prefer-published',action='store_true',
                   help='Use last published snapshot on regular code pushes; upstream only on first publish')
    args=p.parse_args()
    dest=pathlib.Path(args.output);dest.mkdir(parents=True,exist_ok=True)
    if args.prefer_published and reuse_live_snapshot(dest):return
    metadata = {}
    with tempfile.TemporaryDirectory(prefix='hexspindle-feeds-') as td:
        temp=pathlib.Path(td)
        for kind, (url, filename, minimum) in SANS.items():
            source=temp/(kind+'.raw')
            print(f'Download {kind}: {url}', flush=True)
            info=download(url, source, minimum)
            info.update(validate_sans(kind, source))
            info['path']='data/feeds/'+filename
            info['compressed_bytes']=publish_gzip(source,dest/filename)
            info['feed_type']='sans'
            metadata[kind]=info
        for kind, (url, filename) in IANA.items():
            source=temp/(kind+'.json'); info=download(url, source)
            data=json.loads(source.read_text(encoding='utf-8'))
            if not isinstance(data.get('services'), list) or not data['services']:
                raise ValueError(f'{kind}: missing bootstrap service ranges')
            info.update({'path':'data/feeds/'+filename,'compressed_bytes':publish_gzip(source,dest/filename),
                         'feed_type':'iana','records':len(data['services']), 'publication':data.get('publication')})
            metadata[kind]=info
        rir_file=temp/'delegations.tsv'; origins={}; n=0
        with rir_file.open('w',encoding='ascii', errors='replace') as out:
            for name,url in RIRS.items():
                source=temp/(name+'.raw')
                print(f'Download RIR {name}: {url}', flush=True)
                source_meta=download(url,source,min_bytes=50000)
                source_meta.update(parse_rir(source,name,out))
                if name=='arin': source_meta['publisher_md5']=md5_validate_arin(source,temp)
                origins[name]=source_meta
                n+=source_meta['records']
        if n<50000: raise ValueError(f'Unexpectedly few delegation records: {n}')
        with rir_file.open('rb') as hash_input:
            rir_sha256=hashlib.file_digest(hash_input,'sha256').hexdigest()
        info={'source_url': 'five RIR extended-delegated-latest files', 'sources':origins,
              'source_retrieved_at':NOW(), 'raw_bytes':rir_file.stat().st_size,
              'sha256':rir_sha256,
              'records':n, 'format':'pipe-separated', 'feed_type':'rir', 'path':'data/feeds/rir-delegations.tsv.gz'}
        info['compressed_bytes']=publish_gzip(rir_file, dest/'rir-delegations.tsv.gz')
        metadata['rir_delegations']=info
        lite = sync_ipinfo_lite(os.getenv('IPINFO_LITE_TOKEN', '').strip(),temp,dest)
        if lite: metadata['ipinfo_lite'] = lite
        # No abuse.ch exports are published without explicit written-rights acknowledgement.
        from sync_abusech_feeds import publish as publish_abusech
        abuse_key = os.getenv('ABUSECH_AUTH_KEY', '').strip()
        mirror_allowed = os.getenv('ABUSECH_PUBLIC_MIRROR_ALLOWED', '').strip().lower() == 'true'
        unavailable = {}
        if not mirror_allowed:
            reason = ('Authenticated abuse.ch exports are not publicly mirrored. '
                      'Public redistribution permission must be confirmed before enabling publishing.')
            print('::warning title=abuse.ch publishing disabled::' + reason, flush=True)
            unavailable = {kind: reason for kind in ('abusech_threatfox', 'abusech_urlhaus')}
        elif not abuse_key:
            reason = 'ABUSECH_AUTH_KEY Actions secret is missing.'
            print('::warning title=abuse.ch key missing::' + reason, flush=True)
            unavailable = {kind: reason for kind in ('abusech_threatfox', 'abusech_urlhaus')}
        metadata.update(publish_abusech(dest, abuse_key, mirror_allowed))
    write_manifest(dest, metadata, unavailable)
    print('Published:', [(k, v['compressed_bytes']) for k,v in metadata.items()], flush=True)

if __name__=='__main__': main()
