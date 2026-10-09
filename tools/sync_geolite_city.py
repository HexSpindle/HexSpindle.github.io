#!/usr/bin/env python3
"""Optional GeoLite2 City download, validation and *permission-gated* Pages publication.

The default verify-only mode never writes the licensed MMDB to the deployed site.
Set MAXMIND_PUBLIC_MIRROR_ALLOWED=true ONLY with redistribution authorization.
"""
import base64, datetime as dt, gzip, hashlib, io, json, pathlib, re, shutil, subprocess, tarfile, tempfile, urllib.request

URL = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz'
SAFE_URL = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download'
NAME = 'GeoLite2-City.mmdb'
FILENAME = 'geolite2-city.mmdb.gz'
DATASET = 'maxmind_geolite2_city'
MAX_ARCHIVE = 160 * 1024 * 1024
MAX_MMDB = 150 * 1024 * 1024
UTC = dt.timezone.utc

def now():
    return dt.datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')

def fetch_archive(account, key):
    if not account or not key:
        raise ValueError('MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY Actions secrets are required')
    auth = base64.b64encode(f'{account}:{key}'.encode()).decode()
    req = urllib.request.Request(URL, headers={'Authorization':'Basic '+auth, 'Accept-Encoding':'identity',
        'User-Agent':'HexSpindle-FeedSync/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            if getattr(response,'status',200) != 200: raise ValueError('HTTP error')
            archive = response.read(MAX_ARCHIVE + 1)
            if len(archive) > MAX_ARCHIVE: raise ValueError('MaxMind archive size limit exceeded')
            modified = response.headers.get('Last-Modified')
    except Exception:
        # Never include auth, redirect URL or exception details in logs.
        raise RuntimeError('MaxMind download failed. Check access and credentials.') from None
    return archive, modified

def unpack_city(archive):
    if len(archive) > MAX_ARCHIVE: raise ValueError('MaxMind archive exceeds size limit')
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tf:
            members=[m for m in tf.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name == NAME]
            if len(members)!=1 or not 5_000_000 <= members[0].size <= MAX_MMDB:
                raise ValueError('Expected one appropriately sized GeoLite2-City.mmdb')
            with tf.extractfile(members[0]) as stream:
                mmdb=stream.read(MAX_MMDB + 1)
            if len(mmdb)!=members[0].size: raise ValueError('Truncated GeoLite2-City.mmdb')
    except (tarfile.TarError, OSError, EOFError):
        raise ValueError('Invalid or truncated MaxMind tar.gz archive') from None
    if b'\xab\xcd\xefMaxMind.com' not in mmdb[-140000:]:
        raise ValueError('MMDB metadata signature not present')
    return mmdb

def inspect_city(mmdb, inspector=None):
    if inspector is not None:
        result=inspector(mmdb)
    else:
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/NAME
            path.write_bytes(mmdb)
            verifier=pathlib.Path(__file__).with_name('inspect_geolite_city.mjs')
            run=subprocess.run(['node',str(verifier),str(path)],timeout=110,
                capture_output=True,text=True)
            if run.returncode: raise ValueError('GeoLite2 City database metadata failed validation')
            result=json.loads(run.stdout)
    if result.get('database_type')!='GeoLite2-City': raise ValueError('MMDB is not GeoLite2-City')
    epoch=result.get('build_epoch')
    if not isinstance(epoch,(int,float)) or epoch<1451606400 or epoch>dt.datetime.now(UTC).timestamp()+86400:
        raise ValueError('Invalid GeoLite2 City build epoch')
    return result

def process(account, key, permitted, dest, archive_loader=None, inspector=None):
    """Returns (manifest metadata or None, validation record). Does not save if disabled."""
    if not account or not key:
        return None, {'status':'missing_secrets','reason':'Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY'}
    archive, modified = archive_loader(account,key) if archive_loader else fetch_archive(account,key)
    mmdb=unpack_city(archive)
    meta=inspect_city(mmdb,inspector)
    build_at=dt.datetime.fromtimestamp(meta['build_epoch'],UTC).isoformat(timespec='seconds').replace('+00:00','Z')
    checked={'status':'verified_and_published' if permitted else 'verified_not_saved',
        'database_name':NAME,'database_type':meta['database_type'],
        'database_build_at':build_at,'database_updated_date':build_at[:10],
        'mmdb_format_version':meta.get('mmdb_format_version'),
        'raw_bytes':len(mmdb),'sha256':hashlib.sha256(mmdb).hexdigest()}
    if not permitted: return None,checked
    dest=pathlib.Path(dest)
    dest.mkdir(parents=True,exist_ok=True)
    destfile=dest/FILENAME
    with destfile.open('wb') as output:
        with gzip.GzipFile(fileobj=output,mode='wb',compresslevel=6,mtime=0) as out: out.write(mmdb)
    published={**checked,'path':f'data/feeds/{FILENAME}',
        'source_url':SAFE_URL,'source_modified_at':modified,'source_retrieved_at':now(),
        'compressed_bytes':destfile.stat().st_size,'feed_type':'maxmind_geolite2_city',
        'attribution':'GeoLite2 data created by MaxMind — https://www.maxmind.com'}
    published.pop('status')
    return published,checked

def carry_forward(dest, info, fetcher=None, inspector=None, site='https://hexspindle.github.io/'):
    """Copies the LAST VERIFIED public release into the next Pages artifact on non-update days."""
    if not isinstance(info,dict) or info.get('path')!=f'data/feeds/{FILENAME}':
        raise ValueError('Unexpected previous MaxMind feed path')
    if not re.fullmatch(r'[0-9a-f]{64}',info.get('sha256','')): raise ValueError('Missing SHA-256')
    url=site.rstrip('/')+'/'+info['path']
    if fetcher is None:
        with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'HexSpindle-FeedSync/1.0'}),timeout=160) as response:
            blob=response.read(MAX_ARCHIVE+1)
    else:blob=fetcher(url)
    if len(blob)>MAX_ARCHIVE or not blob:raise ValueError('Previous MaxMind artifact missing or oversize')
    raw=gzip.decompress(blob)
    if len(raw)!=info['raw_bytes'] or hashlib.sha256(raw).hexdigest()!=info['sha256']:
        raise ValueError('Existing MaxMind feed does not match its manifest')
    if inspect_city(raw, inspector=inspector)['database_type']!='GeoLite2-City':raise ValueError('Invalid prior database')
    path=pathlib.Path(dest)/FILENAME
    path.write_bytes(blob)
    return dict(info)
