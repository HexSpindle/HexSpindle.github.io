#!/usr/bin/env python3
"""Opt-in abuse.ch exports. No publish unless redistribution permission is confirmed."""
import csv,gzip,hashlib,io,json,pathlib,re,tempfile,urllib.request,zipfile
from datetime import datetime,timezone
from urllib.parse import quote

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')

def request(url):
    # Auth-key is in the export URL as required by abuse.ch: never log URLs/exceptions.
    try:
        req=urllib.request.Request(url,headers={'Accept-Encoding':'identity','User-Agent':'HexSpindle/1.0'})
        with urllib.request.urlopen(req,timeout=150) as response:
            if response.status!=200: raise ValueError('bad HTTP status')
            content=response.read(160*1024*1024+1)
            if len(content)>160*1024*1024:raise ValueError('oversize')
            return content,response.headers.get('Last-Modified')
    except Exception:
        raise RuntimeError('abuse.ch export download failed; review API key, access and service status') from None

def csv_rows(raw):
    if raw.startswith(b'PK'):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos=[x for x in archive.infolist() if x.filename.lower().endswith('.csv') and not x.is_dir()]
            if len(infos)!=1 or infos[0].file_size>350*1024*1024:raise ValueError('Unexpected abuse.ch ZIP CSV')
            with archive.open(infos[0]) as stream:raw=stream.read(350*1024*1024+1)
    if len(raw)>350*1024*1024:raise ValueError('Export too large')
    # ThreatFox CSV uses spaces after commas before quoted values. Without
    # skipinitialspace=True the quotes remain part of the IOC and matching fails.
    rows=csv.reader(io.StringIO(raw.decode('utf-8-sig'),newline=''), skipinitialspace=True)
    keys=None
    for fields in rows:
        if not fields:continue
        # The ThreatFox header is a commented CSV line: # "first_seen_utc",...
        # The first field still has a comment marker and surrounding quotes.
        normalized=[x.strip().lstrip('#').strip().strip('\"').strip().lower().replace(' ','_') for x in fields]
        if keys is None:
            if len(fields)>1 and any(x in normalized for x in ('ioc','ioc_value','url')):keys=normalized
            continue
        if fields[0].startswith('#'):continue
        yield dict(zip(keys,[x.strip() for x in fields]))

def normalize(kind,row):
    if kind=='abusech_threatfox':
        val=row.get('ioc') or row.get('ioc_value')
        if not val or len(val)>2048:return None
        return {'indicator':val,'type':row.get('ioc_type',''),'threat_type':row.get('threat_type',''),
            'malware':row.get('malware_printable') or row.get('malware',''),
            'confidence':row.get('confidence_level',''), 'first_seen':row.get('first_seen') or row.get('first_seen_utc',''),
            'last_seen':row.get('last_seen') or row.get('last_seen_utc',''),'reference':row.get('reference','')}
    val=row.get('url')
    if not val or len(val)>8192 or not re.match(r'^https?://',val,re.I):return None
    return {'indicator':val,'status':row.get('url_status',''), 'date_added':row.get('dateadded') or row.get('date_added',''),
        'last_online':row.get('last_online',''), 'threat':row.get('threat','')}

def publish(dest,key,permitted,download=request):
    if not key or not permitted:return {}
    feeds={
        'abusech_threatfox':('https://threatfox-api.abuse.ch/v2/files/exports/{}/full.csv.zip','abusech-threatfox-iocs.jsonl.gz'),
        'abusech_urlhaus':('https://urlhaus-api.abuse.ch/v2/files/exports/{}/recent.csv','abusech-urlhaus-urls.jsonl.gz'),
    }
    results={}
    for kind,(template,filename) in feeds.items():
        print('Fetching authorized abuse.ch export:',kind,flush=True)
        raw,modified=download(template.format(quote(key,safe='')))
        with tempfile.TemporaryDirectory() as td:
            path=pathlib.Path(td)/'ioc.jsonl'; count=0
            with path.open('w',encoding='utf8') as out:
                for row in csv_rows(raw):
                    obj=normalize(kind,row)
                    if obj is None:continue
                    count+=1
                    if count>1500000:raise ValueError('Export exceeds IOC safety limit')
                    out.write(json.dumps(obj,separators=(',',':'),ensure_ascii=False)+'\n')
            if count<1:raise ValueError('No parseable IOCs in export; refusing publication')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            output=dest/filename
            with path.open('rb') as src,output.open('wb') as dst:
                with gzip.GzipFile(fileobj=dst,mode='wb',mtime=0) as gz:
                    while chunk:=src.read(1024*1024):gz.write(chunk)
            results[kind]={'path':'data/feeds/'+filename,'source_retrieved_at':now(),
                'source_modified_at':modified,'source_url':'https://abuse.ch/',
                'sha256':digest,'raw_bytes':path.stat().st_size,'compressed_bytes':output.stat().st_size,
                'records':count,'feed_type':'abusech','format':'jsonl',
                'attribution':'abuse.ch / Spamhaus — https://abuse.ch',
                'scope':'ThreatFox full historical IOC export (some records are old)' if kind=='abusech_threatfox' else 'URLhaus recent 30 days'}
    return results
