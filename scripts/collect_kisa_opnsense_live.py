"""Read live management transport only; partial evidence never becomes full PASS."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import ssl
import requests
from config_audit.collectors.opnsense import TARGET, ReadOnlyClient, CollectionError
from config_audit.kisa_2026 import PROFILE, assess


def collect(ca_bundle, *, api_credentials_file=None, api_account=None):
    context=ssl.create_default_context(cafile=str(ca_bundle))
    raw={'collected_at':datetime.now(timezone.utc).isoformat(),'origin':'live_management_transport',
         'target':TARGET,'configuration_changes':False,'ports':{}}
    with socket.create_connection(('10.77.40.1',443),timeout=3) as tcp:
        raw['source_ip']=tcp.getsockname()[0]
        with context.wrap_socket(tcp,server_hostname='10.77.40.1') as tls:
            raw['tls']={'protocol':tls.version(),'cipher':tls.cipher()[0],
                        'certificate_sha256':hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest(),
                        'certificate_verified':True,'peer_certificate':tls.getpeercert()}
    session=requests.Session();session.trust_env=False
    for scheme in ('http','https'):
        response=session.get(scheme+'://10.77.40.1/',verify=str(ca_bundle),timeout=(3,5),allow_redirects=False)
        raw[scheme]={'status':response.status_code,'location':response.headers.get('Location'),
                     'body_sha256':hashlib.sha256(response.content).hexdigest(),
                     'plaintext_login_form':scheme=='http' and 'type="password"' in response.text.lower()}
    for port in (22,23):
        try:
            with socket.create_connection(('10.77.40.1',port),timeout=2): result='CONNECTED'
        except (OSError,TimeoutError) as e: result=type(e).__name__
        raw['ports'][str(port)]=result
    if api_credentials_file:
        credentials={}
        for line in api_credentials_file.read_text(encoding='utf-8-sig').splitlines():
            if '=' in line:
                key,value=line.split('=',1);credentials[key.strip()]=value.strip()
        if set(credentials)!={'key','secret'}:
            raise ValueError('existing_opnsense_key_file_invalid')
        client=ReadOnlyClient(account=api_account,key=credentials['key'],secret=credentials['secret'],ca_bundle=str(ca_bundle))
        raw['api']={}
        try:
            for name in ('interfaces','rules','rule_ids'):
                item={'collected_at':datetime.now(timezone.utc).isoformat()}
                try: item.update(status='COLLECTED',data=client.get(name))
                except CollectionError as e: item.update(status='ERROR',error_code=e.error_code,http_status=e.http_status)
                raw['api'][name]=item
        finally:
            client.close();credentials.clear()
    raw['completed_at']=datetime.now(timezone.utc).isoformat()
    https_ok=raw['https']['status']==200
    values={
        'S-06':dict(management_policy_inventory_complete=None,designated_sources_only=None,
                    allowed_source_connected=https_ok,unauthorized_source_denied=None,probe_policy_correlation_complete=None),
        'S-07':dict(management_channels_inventory_complete=None,encrypted_handshake_observed=True,
                    plaintext_management_disabled=None,certificate_or_hostkey_reviewed=True),
    }
    packet={'profile':PROFILE,'observations':[dict(kisa_id=id,asset_id='opnsense',source_kind='SAVED_LAB',collection_status='COLLECTED',product_version=None,collected_at=raw['completed_at'],evidence_reference='opnsense-management-raw.json',value=value) for id,value in values.items()]}
    raw['limitations']=['Actual authorized LAN transport only. Management-interface/PF configuration and independent unauthorized source were not collected.',
                        'TCP timeout alone is not proof of disabled service or management policy.',
                        'Full S-06/S-07 remain NEEDS_REVIEW despite a verified TLS handshake and HTTP redirect.']
    return raw,packet,assess(packet)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ca-bundle',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--api-credentials-file',type=Path,help='Existing local key= / secret= TXT; never exported')
    p.add_argument('--api-account',help='Existing non-root API account label')
    args=p.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    if bool(args.api_credentials_file)!=bool(args.api_account): p.error('API file and account are required together')
    raw,packet,report=collect(args.ca_bundle,api_credentials_file=args.api_credentials_file,api_account=args.api_account)
    for name,data in [('opnsense-management-raw.json',raw),('observations.json',packet),('assessment.json',report)]:
        with (args.output_dir/name).open('x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
    print(json.dumps({'tls':raw['tls']['protocol'],'certificate_verified':True,'http_status':raw['http']['status'],'summary':report['summary']}))


if __name__=='__main__':main()
