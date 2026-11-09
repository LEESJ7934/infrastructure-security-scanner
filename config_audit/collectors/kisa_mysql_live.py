"""Real SQL, role-graph and two-source network evidence from an isolated LAB.

Reuses the existing MySQL image initialization/hardening. The only accepted
project is the new disposable four-container LAB; host networking is forbidden.
Credentials stay in memory/stdin and are never included in returned evidence.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess

from ..kisa_2026 import PROFILE, assess

PROJECT = 'scanner-kisa-mysql'
ADDRESS = '172.30.96.10'
ALLOWED = '172.30.96.20'
DENIED = '172.30.96.30'
ROOT = Path(__file__).resolve().parents[2]


def command(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, capture_output=True, text=True,
                            encoding='utf-8', timeout=45, shell=False)
    if len(result.stdout) > 2*1024*1024 or check and result.returncode != 0:
        raise ValueError('selected_mysql_query_failed')
    return result


def scope():
    context = command(['docker','context','show']).stdout.strip()
    if context not in ('default','desktop-linux'):
        raise ValueError('local_docker_required')
    endpoint = json.loads(command(['docker','context','inspect',context]).stdout)[0]['Endpoints']['docker']['Host']
    if endpoint not in ('unix:///var/run/docker.sock','npipe:////./pipe/docker_engine','npipe:////./pipe/dockerDesktopLinuxEngine'):
        raise ValueError('local_docker_required')
    args = ['docker','--context',context]
    nodes = {}
    for service in ('mysql','gate','allowed','denied'):
        obj = json.loads(command(args+['inspect',PROJECT+'-'+service+'-1']).stdout)[0]
        host, cfg = obj['HostConfig'], obj['Config']
        labels = cfg.get('Labels',{})
        if (labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.service') != service
                or obj['State']['Running'] is not True or host.get('Privileged')
                or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'
                or any((host.get('PortBindings') or {}).values())
                or any(m.get('Type') != 'tmpfs' for m in obj.get('Mounts',[]))):
            raise ValueError('foreign_or_unsafe_selected_mysql_container')
        expected_caps = {'NET_ADMIN'} if service=='gate' else {'CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'} if service=='mysql' else set()
        if set(host.get('CapAdd') or []) != expected_caps or set(host.get('CapDrop') or []) != {'ALL'}:
            raise ValueError('selected_mysql_capabilities_invalid')
        nodes[service] = obj
    net = json.loads(command(args+['network','inspect',PROJECT+'_isolated']).stdout)[0]
    if (net.get('Internal') is not True or net.get('Driver') != 'bridge'
            or set(net.get('Containers',{})) != {nodes[s]['Id'] for s in ('gate','allowed','denied')}
            or nodes['mysql']['HostConfig'].get('NetworkMode') != 'container:'+nodes['gate']['Id']):
        raise ValueError('selected_mysql_network_invalid')
    for service, ip in (('gate', ADDRESS), ('allowed', ALLOWED), ('denied', DENIED)):
        networks = nodes[service]['NetworkSettings']['Networks']
        if set(networks) != {PROJECT+'_isolated'} or networks[PROJECT+'_isolated']['IPAddress'] != ip:
            raise ValueError('selected_mysql_source_ip_invalid')
    if any(nodes[s]['Image'] != nodes['mysql']['Image'] for s in ('allowed','denied')):
        raise ValueError('selected_mysql_client_image_mismatch')
    return args, nodes


def principal(grantee):
    match = re.fullmatch(r"'([^']*)'@'([^']*)'", grantee)
    if not match:
        raise ValueError('mysql_grantee_unrecognized')
    return '@'.join(match.groups())


def role_privileges(accounts, static, dynamic, roles, proxies, mandatory):
    """Expand inherited global privileges and proxy edges; detect cycles safely."""
    keys = {a['user']+'@'+a['host'] for a in accounts}
    privilege = {k:set() for k in keys}
    edges = {k:set() for k in keys}
    for row in static:
        key = principal(row['grantee'])
        if key not in keys: raise ValueError('global_privilege_account_missing')
        if row['privilege'] != 'USAGE': privilege[key].add(row['privilege'])
    for row in dynamic:
        key = row['user']+'@'+row['host']
        if key not in keys: raise ValueError('dynamic_privilege_account_missing')
        privilege[key].add(row['privilege'])
    for row in roles:
        origin = row['from_user']+'@'+row['from_host']; target = row['to_user']+'@'+row['to_host']
        if origin not in keys or target not in keys: raise ValueError('role_account_missing')
        edges[target].add(origin)
    for row in proxies:
        origin=row['proxied_user']+'@'+row['proxied_host']; target=row['user']+'@'+row['host']
        if origin not in keys or target not in keys: raise ValueError('proxy_account_missing')
        edges[target].add(origin)
    # Bounded fixed point handles cycles without dropping inherited privileges.
    for _ in range(len(keys)+1):
        changed=False
        for key in keys:
            inherited=set().union(*(privilege[p] for p in edges[key])) if edges[key] else set()
            if not inherited <= privilege[key]: privilege[key] |= inherited; changed=True
        if not changed: break
    return {k:sorted(v) for k,v in privilege.items()}, mandatory == ''


def restricted_ruleset(ruleset):
    entries = ruleset.get('nftables',[])
    tables = [x['table'] for x in entries if 'table' in x]
    chains = [x['chain'] for x in entries if 'chain' in x]
    rules = [x['rule'] for x in entries if 'rule' in x]
    if len(tables)!=1 or tables[0].get('family')!='inet' or tables[0].get('name')!='kisa_mysql': return False
    if len(chains)!=1 or chains[0].get('hook')!='input' or chains[0].get('type')!='filter' or len(rules)!=3: return False
    patterns=[]
    for rule in rules:
        if rule.get('table')!='kisa_mysql' or rule.get('chain')!='input': return False
        matches=[]; verdict=None
        for expression in rule.get('expr',[]):
            if 'match' in expression:
                m=expression['match']
                if m.get('op')!='==': return False
                matches.append((json.dumps(m.get('left'),sort_keys=True),m.get('right')))
            elif 'accept' in expression: verdict='accept'
            elif 'drop' in expression: verdict='drop'
            elif 'counter' not in expression: return False
        patterns.append((matches,verdict))
    ip=json.dumps({'payload':{'protocol':'ip','field':'saddr'}},sort_keys=True)
    port=json.dumps({'payload':{'protocol':'tcp','field':'dport'}},sort_keys=True)
    interface=json.dumps({'meta':{'key':'iifname'}},sort_keys=True)
    return patterns == [([(ip,ALLOWED),(port,3306)],'accept'), ([(interface,'lo')],'accept'), ([(port,3306)],'drop')]


def normalize(raw):
    purposes = json.loads((ROOT/'lab/kisa-mysql-selected/account-purposes.json').read_text(encoding='utf-8'))
    accounts=raw['sql']['accounts']; keys={a['user']+'@'+a['host'] for a in accounts}
    complete=bool(accounts) and len(accounts)==raw['sql']['account_count'] and len(keys)==len(accounts)
    reviewed=complete and keys == set(purposes['accounts'])
    unused=[a for a in accounts if a['user']+'@'+a['host'] not in purposes['accounts'] and a['locked']!='Y']
    effective,expanded=role_privileges(accounts,raw['sql']['global_privileges'],raw['sql']['dynamic_privileges'],raw['sql']['roles'],raw['sql']['proxies'],raw['sql']['mandatory_roles'])
    admins=set(purposes['authorized_global_privilege_principals'])
    excess={k:v for k,v in effective.items() if v and k not in admins}
    locked_ok=all(a['locked']=='Y' for a in accounts if a['user']+'@'+a['host'] in purposes['system_accounts_require_locked'])
    host_ok=all(a['host'] in ('localhost','127.0.0.1','::1',ALLOWED) for a in accounts if a['locked']!='Y')
    probes=raw['probes']
    values={
        'D-02':dict(account_inventory_complete=complete,account_purposes_reviewed=reviewed,unnecessary_unlocked_accounts_absent=not unused and locked_ok),
        'D-04':dict(privilege_inventory_complete=complete,role_and_proxy_expansion_complete=expanded,admin_purposes_reviewed=reviewed,unauthorized_admin_privileges_absent=not excess),
        'D-10':dict(account_host_inventory_complete=complete,designated_ip_policy_only=host_ok and restricted_ruleset(raw['nft_ruleset']),allowed_source_connected=probes['allowed']['tcp_connected'] and probes['allowed']['sql_select_succeeded'],unauthorized_source_denied=not probes['denied']['tcp_connected'] and probes['denied']['returncode']==124,network_policy_inventory_complete=raw['network_scope_verified']),
    }
    packet={'profile':PROFILE,'observations':[dict(kisa_id=id,asset_id='mysql',source_kind='SAVED_LAB',collection_status='COLLECTED',product_version=raw['sql']['version'],collected_at=raw['collected_at'],evidence_reference='mysql-live-raw.json',value=value) for id,value in values.items()]}
    return packet, {'effective_global_privileges':effective,'excess_global_privileges':excess,'purposes_reviewed':reviewed}


def collect():
    args,nodes=scope()
    def execute(service,cmd,**kw): return command(args+['exec','-i',nodes[service]['Id']]+cmd,**kw)
    def sql(q):
        value=execute('mysql',['mysql','--defaults-extra-file=/run/lab/client.cnf','--batch','--raw','--skip-column-names','--execute='+q]).stdout.strip()
        return json.loads(value)
    queries={
        'accounts':"SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('user',User,'host',Host,'locked',account_locked)),JSON_ARRAY()) FROM mysql.user",
        'global_privileges':"SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('grantee',GRANTEE,'privilege',PRIVILEGE_TYPE,'grantable',IS_GRANTABLE)),JSON_ARRAY()) FROM INFORMATION_SCHEMA.USER_PRIVILEGES",
        'dynamic_privileges':"SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('user',USER,'host',HOST,'privilege',PRIV,'grantable',WITH_GRANT_OPTION)),JSON_ARRAY()) FROM mysql.global_grants",
        'roles':"SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('from_user',FROM_USER,'from_host',FROM_HOST,'to_user',TO_USER,'to_host',TO_HOST,'admin_option',WITH_ADMIN_OPTION)),JSON_ARRAY()) FROM mysql.role_edges",
        'proxies':"SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('user',User,'host',Host,'proxied_user',Proxied_user,'proxied_host',Proxied_host,'grantable',With_grant)),JSON_ARRAY()) FROM mysql.proxies_priv",
        'account_count':"SELECT COUNT(*) FROM mysql.user",
        'version':"SELECT JSON_QUOTE(VERSION())",
        'mandatory_roles':"SELECT JSON_QUOTE(@@GLOBAL.mandatory_roles)",
    }
    observed={name:sql(q) for name,q in queries.items()}
    # Read one generated ephemeral client config, pipe over stdin, never return it.
    credential=execute('mysql',['cat','/run/lab/probe.cnf']).stdout
    probes={}
    for service,ip in (('allowed',ALLOWED),('denied',DENIED)):
        start=datetime.now(timezone.utc).isoformat()
        tcp=execute(service,['timeout','4','bash','-c','exec 3<>/dev/tcp/'+ADDRESS+'/3306'],check=False)
        result=execute(service,['bash','-c','umask 077; cfg=$(mktemp /tmp/kisa-client.XXXXXX); trap \'rm -f "$cfg"\' EXIT; cat > "$cfg"; mysql --defaults-extra-file="$cfg" --batch --skip-column-names --execute="SELECT COUNT(*) FROM lab_data.items"'],data=credential,check=False) if service=='allowed' else None
        probes[service]={'source_ip':ip,'destination_ip':ADDRESS,'port':3306,'tcp_connected':tcp.returncode==0,'returncode':tcp.returncode,'sql_select_succeeded':result is not None and result.returncode==0 and result.stdout.strip()=='0','started_at':start,'ended_at':datetime.now(timezone.utc).isoformat()}
    credential=None
    nft=json.loads(execute('gate',['nft','-j','list','ruleset']).stdout)
    raw={'origin':'local_container_readonly','project':PROJECT,'collected_at':datetime.now(timezone.utc).isoformat(),
         'network_scope_verified':True,'sql':observed,'queries':queries,'probes':probes,'nft_ruleset':nft,
         'images':{k:v['Image'] for k,v in nodes.items()},
         'limitations':['Fixed isolated MySQL LAB only; no customer or host firewall claim.','No password, credential file or authentication hash is exported.']}
    packet,analysis=normalize(raw)
    return raw,packet,assess(packet),analysis
