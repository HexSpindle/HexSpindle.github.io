#!/usr/bin/env python3
"""MaxMind licensed City MMDB private refresher. Never publish to GitHub Pages."""
import base64,hashlib,io,json,os,pathlib,re,subprocess,tarfile,tempfile,urllib.request
from datetime import datetime,timezone

URL='https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz'

def refresh(account,key,bucket='',region='us-east-1',downloader=None,uploader=None):
    if not account or not key:return {'status':'skipped','reason':'Configure MaxMind account ID and license key secrets'}
    if downloader is None:
        auth=base64.b64encode(f'{account}:{key}'.encode()).decode()
        req=urllib.request.Request(URL,headers={'Authorization':'Basic '+auth,'Accept-Encoding':'identity'})
        try:
            with urllib.request.urlopen(req,timeout=180) as resp:archive=resp.read(160*1024*1024+1)
        except Exception:raise RuntimeError('MaxMind download failed: check credentials and account access') from None
    else:archive=downloader()
    if len(archive)>160*1024*1024:raise ValueError('MaxMind archive too large')
    try:
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tf:
            files=[m for m in tf.getmembers() if m.isfile() and m.name.endswith('/GeoLite2-City.mmdb')]
            if len(files)!=1 or files[0].size>260*1024*1024:raise ValueError('Unexpected City archive contents')
            mmdb=tf.extractfile(files[0]).read(files[0].size+1)
            if len(mmdb)!=files[0].size:raise ValueError('Truncated MMDB')
    except (tarfile.TarError,OSError):raise ValueError('Invalid MaxMind tar archive') from None
    if b'\xab\xcd\xefMaxMind.com' not in mmdb[-140000:]:raise ValueError('MMDB metadata signature missing')
    digest=hashlib.sha256(mmdb).hexdigest()
    result={'status':'verified_not_retained','sha256':digest,'size_bytes':len(mmdb),'retrieved_at':datetime.now(timezone.utc).isoformat()}
    if not bucket:return result
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,62}',bucket):raise ValueError('Invalid private bucket')
    with tempfile.TemporaryDirectory() as td:
        file=pathlib.Path(td)/'GeoLite2-City.mmdb';file.write_bytes(mmdb);file.chmod(0o600)
        if uploader:uploader(file,bucket,digest)
        else:
            # Fail closed: do not upload licensed GeoLite data into a publicly readable bucket.
            check=subprocess.run(['aws','s3api','get-public-access-block','--bucket',bucket,'--region',region],
                capture_output=True,text=True,check=True,timeout=30)
            flags=json.loads(check.stdout)['PublicAccessBlockConfiguration']
            if not all(flags.get(k) for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')):
                raise RuntimeError('MaxMind destination must have all four S3 Block Public Access controls enabled')
            old=subprocess.run(['aws','s3api','head-object','--bucket',bucket,
                '--key','hexspindle/private/GeoLite2-City.mmdb','--region',region,
                '--query','Metadata.sha256','--output','text'],capture_output=True,text=True,timeout=30)
            if old.returncode == 0 and old.stdout.strip()==digest:
                result['status']='already_current_private_s3';return result
            subprocess.run(['aws','s3','cp',str(file),f's3://{bucket}/hexspindle/private/GeoLite2-City.mmdb',
                '--region',region,'--sse','AES256','--no-progress','--metadata',f'sha256={digest}'],
                check=True,capture_output=True,text=True,timeout=240)
    result['status']='stored_in_private_s3'
    return result

if __name__=='__main__':
    result=refresh(os.getenv('MAXMIND_ACCOUNT_ID',''),os.getenv('MAXMIND_LICENSE_KEY',''),
        os.getenv('PRIVATE_MAXMIND_S3_BUCKET',''),os.getenv('AWS_REGION','us-east-1'))
    print(json.dumps(result,sort_keys=True))
    with open(os.getenv('GITHUB_STEP_SUMMARY','/dev/null'),'a') as f:
        f.write('### GeoLite2 City private sync\n\nStatus: '+result['status']+'\n\nNever published to GitHub Pages.\n')
