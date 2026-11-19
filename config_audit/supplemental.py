"""Opt-in interpretation of bounded, sanitized authenticated evidence.

No commands, network, hardening or arbitrary predicates. These are internal
criteria, never automatic KISA item mappings or authenticated origin claims.
Raw account names and effective SSH text are reduced before export.
"""
from datetime import datetime, timezone
from uuid import uuid4
from .engine import evaluate
from .models import AuditAsset, AuditRule, Observation
from .collectors.linux_ssh import parse_ssh_settings

VERSION = 'supplemental-evidence-1'
RULES = {
 'LINUX-ACCOUNT-UID0': ('linux', 'Only the explicitly designated root account has UID 0', 'Review unexpected UID 0 accounts and account purpose before changes.'),
 'LINUX-SSH-ROOT-CONTEXTS': ('linux', 'PermitRootLogin no in every supplied approved effective SSH context', 'Review sshd -T -C for each relevant user/source/host, Include and Match context.'),
 'LINUX-SSH-PASSWORD-CONTEXTS': ('linux', 'PasswordAuthentication no in every supplied approved effective SSH context', 'Review effective contexts and preserve key-based recovery access before changes.'),
 'LINUX-LOG-DELIVERY': ('linux', 'A unique current-run marker arrived at the explicitly named log destination', 'Verify actual current-run delivery and retention, not daemon presence alone.'),
 'MYSQL-TLS-SESSION': ('mysql', 'TCP session cipher and protocol observed, peer identity verified by the client', 'Require TCP TLS and client identity verification; socket policy alone is insufficient.'),
}


def _require(ok):
    if not ok:raise ValueError('supplemental_evidence_invalid')


def normalize(check, value):
    _require(isinstance(value, dict))
    if check == 'LINUX-ACCOUNT-UID0':
        _require(set(value)=={'accounts','designated_root'} and isinstance(value['accounts'],list)
                 and 0<len(value['accounts'])<=10000 and isinstance(value['designated_root'],str))
        rows=value['accounts'];seen=set();privileged=[]
        for row in rows:
            _require(isinstance(row,dict) and set(row)=={'name','uid'} and isinstance(row['name'],str)
                     and 0<len(row['name'])<=128 and type(row['uid']) is int and 0<=row['uid']<=2**32)
            _require(row['name'] not in seen);seen.add(row['name'])
            if row['uid']==0:privileged.append(row['name'])
        return {'criterion_met':privileged==[value['designated_root']], 'account_count':len(rows), 'uid0_count':len(privileged)}
    if check.startswith('LINUX-SSH-'):
        _require(set(value)=={'expected_contexts','effective_outputs'} and isinstance(value['expected_contexts'],list)
                 and 0<len(value['expected_contexts'])<=128 and all(isinstance(v,str) for v in value['expected_contexts'])
                 and isinstance(value['effective_outputs'],dict))
        expected=value['expected_contexts'];outputs=value['effective_outputs']
        _require(len(expected)==len(set(expected)))
        key='permitrootlogin' if 'ROOT' in check else 'passwordauthentication'
        states=[]
        for ctx,raw in outputs.items():
            _require(isinstance(ctx,str) and isinstance(raw,str) and len(raw)<=16384)
            item=parse_ssh_settings(raw)[key]
            states.append(None if item.collection_error or item.observed_value in (None,'unrecognized') else item.observed_value=='no')
        complete=set(expected)==set(outputs)
        met=False if False in states else None if not complete or not states or None in states else True
        return {'criterion_met':met,'expected_context_count':len(expected),'observed_context_count':len(outputs),'context_inventory_complete':complete}
    if check == 'LINUX-LOG-DELIVERY':
        keys={'probe_id','observed_probe_id','probe_at','received_at','destination','destination_matches'}
        _require(set(value)==keys and all(isinstance(value[k],str) for k in keys-{'destination_matches'})
                 and type(value['destination_matches']) is bool)
        start=datetime.fromisoformat(value['probe_at']);end=datetime.fromisoformat(value['received_at'])
        _require(start.utcoffset() is not None and end.utcoffset() is not None and bool(value['destination']))
        met=bool(value['probe_id']) and value['probe_id']==value['observed_probe_id'] and start<=end and value['destination_matches']
        return {'criterion_met':met,'marker_correlated':value['probe_id']==value['observed_probe_id'],
                'destination_matches':value['destination_matches'],'delivery_latency_seconds':(end-start).total_seconds()}
    if check == 'MYSQL-TLS-SESSION':
        _require(set(value)=={'transport','ssl_cipher','ssl_version','peer_identity_verified'}
                 and value['transport'] in {'TCP','SOCKET'} and isinstance(value['ssl_cipher'],str)
                 and isinstance(value['ssl_version'],str) and (value['peer_identity_verified'] is None or type(value['peer_identity_verified']) is bool))
        # A socket observation is not a negative network TLS test.
        met=None if value['transport']!='TCP' else False if not value['ssl_cipher'] or not value['ssl_version'] else value['peer_identity_verified']
        return {'criterion_met':met,'transport':value['transport'],'cipher_observed':bool(value['ssl_cipher']),
                'tls_protocol_observed':bool(value['ssl_version']),'peer_identity_verified':value['peer_identity_verified']}
    raise ValueError('supplemental_check_unsupported')


def assess(document):
    _require(isinstance(document,dict) and set(document)=={'schema_version','origin','items'}
             and document['schema_version']==1 and type(document['schema_version']) is int
             and document['origin'] in {'SYNTHETIC','SAVED_LAB','MANUAL_LAB'} and isinstance(document['items'],list)
             and len(document['items'])<=1000)
    now=datetime.now(timezone.utc);run=str(uuid4());results=[];seen=set()
    for item in document['items']:
        _require(isinstance(item,dict) and set(item)<={'check_id','asset_id','product_version','value','collection_status',
                 'collected_at','evidence_reference','scope','complete','supported','review_reason'})
        check=item.get('check_id');_require(check in RULES)
        asset=item.get('asset_id');_require(isinstance(asset,str) and 0<len(asset)<=128 and (asset,check) not in seen);seen.add((asset,check))
        state=item.get('collection_status');_require(state in {'COLLECTED','NOT_TESTED','ERROR'})
        stamp=item.get('collected_at');when=datetime.fromisoformat(stamp) if isinstance(stamp,str) else None
        _require(when is None or when.utcoffset() is not None and when<=now)
        reference=item.get('evidence_reference');scope=item.get('scope')
        meta_ok=when is not None and isinstance(reference,str) and bool(reference.strip()) and isinstance(scope,str) and bool(scope.strip())
        value=normalize(check,item.get('value')) if state=='COLLECTED' else None
        product,criterion,recommendation=RULES[check]
        observation=Observation(value,reference,state=='ERROR',collected_at=when,source_kind=document['origin'],
            collection_scope=scope,collection_complete=item.get('complete',False),supported=item.get('supported',False),
            review_reason=item.get('review_reason') or (None if meta_ok or state!='COLLECTED' else 'collection_metadata_missing'))
        result=evaluate(AuditAsset(asset,product,item.get('product_version')),AuditRule(check,VERSION,criterion,recommendation,
            condition=lambda v:v['criterion_met'],product=product,standard_reference='Internal supplemental criterion; no automatic KISA mapping'),
            observation,execution_id=run,checked_at=now)
        results.append({**result.to_safe_dict(),'observed_value':value,'expected_condition':criterion,'recommendation':recommendation,
            'evidence_reference':reference,'source_authenticity':'NOT_INDEPENDENTLY_VERIFIED','standard_reference':result.standard_reference})
    return {'schema_version':1,'origin':document['origin'],'mode':'OFFLINE_SUPPLEMENTAL_EVIDENCE','generated_at':now.isoformat(),
        'results':results,'limitations':['No source commands or actual network tests are performed by this evaluator.',
        'Completeness and scope are input declarations. Original evidence and scope require operator review.',
        'Synthetic results never establish actual remediation. No automatic KISA equivalence.']}
