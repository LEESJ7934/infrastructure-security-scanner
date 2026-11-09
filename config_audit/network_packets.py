"""Project-scoped, header-only ICMP path probes. No firewall/route mutations.

Configuration verdicts are references only. Packet PASS requires bidirectional
replies, actual router TTL forwarding, selected routes and forward rules.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess

from .collectors import network_devices as net

PROFILES = {
    "existing": {"project":"scanner-p2net", "a":"10.203.10.10", "b":"10.203.20.10",
        "ga":"10.203.10.254", "gb":"10.203.20.254", "table":"phase2_guard", "if_a":"data0", "if_b":"data1",
        "networks":{"management":"10.203.0.0/24","data_a":"10.203.10.0/24","data_b":"10.203.20.0/24"}},
    "fabric": {"project":"scanner-p2pkt", "a":"10.204.10.10", "b":"10.204.20.10",
        "ga":"10.204.10.254", "gb":"10.204.20.254", "table":"phase2_packet_guard", "if_a":"data0", "if_b":"data0",
        "networks":{"fabric":"10.204.0.0/16"}},
}


def prefix():
    context=net._run(["docker","context","show"]).strip()
    net.require(context in {"default","desktop-linux"},"local_context_required")
    info=json.loads(net._run(["docker","context","inspect",context]))
    endpoint=info[0]["Endpoints"]["docker"]["Host"]
    net.require(endpoint in {"unix:///var/run/docker.sock","npipe:////./pipe/docker_engine","npipe:////./pipe/dockerDesktopLinuxEngine"},"local_context_required")
    args=["docker","--context",context]
    net.require(net._run(args+["info","--format","{{.OSType}}"] ).strip()=="linux","linux_engine_required")
    return args


def scope(args, profile):
    cfg=PROFILES[profile];project=cfg["project"];ids={};names={}
    for service in ("router","client-a","client-b"):
        name=project+"-"+service+"-1";info=json.loads(net._run(args+["inspect",name]))[0]
        labels=info.get("Config",{}).get("Labels",{});host=info.get("HostConfig",{})
        net.require(labels.get("com.docker.compose.project")==project and labels.get("com.docker.compose.service")==service,"foreign_container_rejected")
        net.require(info.get("State",{}).get("Running") is True,"packet_container_not_running")
        net.require(not host.get("Privileged") and host.get("NetworkMode")!="host"
                    and host.get("PidMode")!="host" and host.get("IpcMode")!="host" and not info.get("Mounts")
                    and not any((host.get("PortBindings") or {}).values()),"unsafe_packet_scope")
        caps={item.removeprefix("CAP_") for item in host.get("CapAdd") or []}
        net.require(not caps & {"SYS_ADMIN","SYS_MODULE","SYS_PTRACE"},"unsafe_packet_scope")
        expected=set(cfg["networks"]) if profile=="fabric" or service=="router" else {"data_a" if service=="client-a" else "data_b"}
        net.require(set(info.get("NetworkSettings",{}).get("Networks",{}))=={project+"_"+item for item in expected},"unexpected_network_membership")
        ids[service]=info["Id"];names[service]=name
    networks=[]
    for suffix,cidr in cfg["networks"].items():
        info=json.loads(net._run(args+["network","inspect",project+"_"+suffix]))[0]
        net.require(info.get("Labels",{}).get("com.docker.compose.project")==project and info.get("Internal") is True and info.get("Driver")=="bridge","network_scope_invalid")
        subnets=[item.get("Subnet") for item in info.get("IPAM",{}).get("Config",[])]
        net.require(subnets==[cidr],"packet_subnet_mismatch")
        expected=set(ids.values()) if suffix=="fabric" else {ids["router"]} if suffix=="management" else {ids["router"],ids["client-a" if suffix=="data_a" else "client-b"]}
        net.require(set(info.get("Containers",{}))==expected,"unexpected_network_endpoints")
        networks.append({"name":project+"_"+suffix,"internal":True,"driver":"bridge","subnet":cidr})
    return names,networks


def ping_stats(text, code):
    match=re.search(r'(\d+) packets transmitted,\s*(\d+) (?:packets )?received',text)
    if match is None or code not in (0,1):return {"status":"ERROR","sent":None,"received":None,"loss_percent":None}
    sent,received=map(int,match.groups())
    if sent!=3 or not 0<=received<=sent:return {"status":"ERROR","sent":None,"received":None,"loss_percent":None}
    return {"status":"PASS" if received==sent else "FAIL","sent":sent,"received":received,"loss_percent":100*(sent-received)/sent}


def forward_rules(document, cfg):
    net.require(isinstance(document,dict) and isinstance(document.get('nftables'),list),'forward_json_invalid')
    rows=document.get("nftables",[])
    net.require(all(isinstance(row,dict) for row in rows),'forward_json_invalid')
    target=("inet",cfg["table"],"forward")
    chains=[row["chain"] for row in rows if isinstance(row.get("chain"),dict) and
            (row["chain"].get("family"),row["chain"].get("table"),row["chain"].get("name"))==target]
    expected=[(cfg["if_a"],cfg["if_b"],str(ipaddress.ip_network(cfg["a"]+'/24',strict=False)),str(ipaddress.ip_network(cfg["b"]+'/24',strict=False))),
              (cfg["if_b"],cfg["if_a"],str(ipaddress.ip_network(cfg["b"]+'/24',strict=False)),str(ipaddress.ip_network(cfg["a"]+'/24',strict=False)))]
    found=set();unknown=0
    def cidr(value):
        if isinstance(value,dict) and set(value)=={"prefix"}:value=str(value["prefix"]["addr"])+"/"+str(value["prefix"]["len"])
        return str(ipaddress.ip_network(value,strict=False))
    for row in rows:
        rule=row.get("rule",{})
        if (rule.get("family"),rule.get("table"),rule.get("chain"))!=target:continue
        expr=[item for item in rule.get("expr",[]) if set(item)!={"counter"}]
        fields={}
        try:
            if len(expr)!=5 or expr[-1]!={"accept":None}:raise ValueError()
            for item in expr[:-1]:
                m=item["match"]
                if m["op"]!="==":raise ValueError()
                left=m["left"]
                key=left.get("meta",{}).get("key")
                if key in ("iifname","oifname"):fields[key]=m["right"]
                elif left.get("payload",{}).get("protocol")=="ip" and left["payload"].get("field") in ("saddr","daddr"):
                    fields[left["payload"]["field"]]=cidr(m["right"])
                else:raise ValueError()
            value=tuple(fields[k] for k in ("iifname","oifname","saddr","daddr"))
            if value not in expected:raise ValueError()
            found.add(expected.index(value))
        except (KeyError,TypeError,ValueError):unknown+=1
    valid_chain=len(chains)==1 and chains[0].get("type")=="filter" and chains[0].get("hook")=="forward" and chains[0].get("policy")=="drop" and (type(chains[0].get('prio')) is int and chains[0]['prio']==0 or chains[0].get('prio')=='filter')
    return {"status":"PASS" if valid_chain and found=={0,1} and unknown==0 else "NEEDS_REVIEW",
            "default_drop":bool(valid_chain),"a_to_b_rule":0 in found,"b_to_a_rule":1 in found,"unrecognized_rules":unknown,
            "scope":"owned_forward_chain_configuration_only"}


def path_points(events, source, destination):
    def selected(node,direction,kind,src,dst):
        return [e for e in events[node] if e["direction"]==direction and e["icmp_type"]==kind and e["source"]==src and e["destination"]==dst]
    points={
        "source_request_out":selected("source","out",8,source,destination),
        "router_request_in":selected("router","in",8,source,destination),
        "router_request_out":selected("router","out",8,source,destination),
        "destination_request_in":selected("destination","in",8,source,destination),
        "destination_reply_out":selected("destination","out",0,destination,source),
        "router_reply_in":selected("router","in",0,destination,source),
        "router_reply_out":selected("router","out",0,destination,source),
        "source_reply_in":selected("source","in",0,destination,source)}
    def hop(first,last,expected):
        matched={(a['id'],a['sequence']) for a in first for b in last
                 if a['id']==b['id'] and a['sequence']==b['sequence'] and a['ttl']==b['ttl']+1}
        # Every one of the three request/reply sequences must traverse Router;
        # a single routed echo must not hide subsequent L2/redirect bypasses.
        required={(event['id'],event['sequence']) for event in expected}
        return len(required)>=3 and required<=matched
    counts={key:len(value) for key,value in points.items()}
    request_hop=hop(points['router_request_in'],points['router_request_out'],points['source_request_out'])
    reply_hop=hop(points['router_reply_in'],points['router_reply_out'],points['destination_reply_out'])
    gap=next((key for key,value in counts.items() if not value),None)
    return {"counts":counts,"router_request_ttl_hop_verified":request_hop,"router_reply_ttl_hop_verified":reply_hop,
            "first_missing_stage":gap,"router_path_verified":request_hop and reply_hop}


class Capture:
    def __init__(self, args, name, source, destination):
        program=(Path(__file__).resolve().parents[1]/"lab/network-packet-lab/capture.py").read_text(encoding='utf-8')
        self.process=subprocess.Popen(args+["exec","-i",name,"python3","-u","-c",program,source,destination],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
        with ThreadPoolExecutor(max_workers=1) as pool:
            ready=pool.submit(self.process.stdout.readline,4096)
            try:net.require(json.loads(ready.result(timeout=8))=={"ready":True},"capture_not_ready")
            except Exception:
                self.process.kill();self.process.wait(timeout=3);raise net.NetworkInputError('capture_not_ready') from None
    def go(self):self.process.stdin.write('GO\n');self.process.stdin.flush()
    def finish(self):
        try:
            raw,_=self.process.communicate(timeout=14)
            net.require(self.process.returncode==0 and len(raw)<=65536,"capture_failed")
            result=json.loads(raw)
            net.require(isinstance(result.get('events'),list) and len(result['events'])<=128,"capture_invalid")
            return result['events']
        except (ValueError,OSError,subprocess.SubprocessError):
            self.abort();raise net.NetworkInputError('capture_failed') from None
    def abort(self):
        if self.process.poll() is None:self.process.kill()
        try:self.process.communicate(timeout=3)
        except (OSError,subprocess.SubprocessError):pass


def probe(args,names,cfg,reverse=False):
    source,destination=(cfg['b'],cfg['a']) if reverse else (cfg['a'],cfg['b'])
    source_node,destination_node=('client-b','client-a') if reverse else ('client-a','client-b')
    captures={}
    try:
        # Open all sockets before GO so command startup does not lose the first echo.
        for role,node in [('source',source_node),('router','router'),('destination',destination_node)]:
            captures[role]=Capture(args,names[node],source,destination)
        for capture in captures.values():capture.go()
        done=subprocess.run(args+['exec',names[source_node],'env','LC_ALL=C','ping','-c','3','-W','1',destination],capture_output=True,text=True,timeout=8,encoding='utf-8')
        stats=ping_stats(done.stdout,done.returncode)
        events={key:capture.finish() for key,capture in captures.items()}
        return {'source':source,'destination':destination,'ping':stats,'path':path_points(events,source,destination),'header_events':events,'payload_saved':False}
    finally:
        for capture in captures.values():capture.abort()


def configuration_reference(path):
    if path is None:return None
    doc,digest=net._load_document(path)
    net.require(isinstance(doc,dict) and isinstance(doc.get('results'),list),'configuration_reference_invalid')
    states={row['check_id']:row['status'] for row in doc['results'] if isinstance(row,dict) and row.get('check_id') in ('NET-LAB-R03','NET-LAB-R04') and row.get('status') in ('PASS','FAIL','NEEDS_REVIEW','ERROR','NOT_TESTED','NOT_APPLICABLE')}
    return {'sha256':digest,'recorded_configuration_statuses':states,'original_file_modified':False,'scope':'original_scanner_p2net_only_not_packet_lab_configuration'}


def collect(profile,config_path=None):
    net.require(profile in PROFILES,'profile_invalid')
    cfg=PROFILES[profile];args=prefix();names,networks=scope(args,profile)
    def read(node,cmd):return net._run(args+['exec',names[node]]+cmd)
    snapshots={}
    for node in ('router','client-a','client-b'):
        snapshots[node]={'addresses':json.loads(read(node,['ip','-j','address','show'])),
            'routes':json.loads(read(node,['ip','-j','route','show'])),
            'neighbors':json.loads(read(node,['ip','-j','neigh','show']))}
    selected_routes={node:json.loads(read(node,['ip','-j','route','get',cfg['b'] if node=='client-a' else cfg['a']])) for node in ('client-a','client-b')}
    route_verified=all(len(selected_routes[node])==1 and selected_routes[node][0].get('gateway')==cfg['ga' if node=='client-a' else 'gb'] for node in selected_routes)
    forwarding=read('router',['cat','/proc/sys/net/ipv4/ip_forward']).strip()
    document=json.loads(read('router',['nft','-j','list','chain','inet',cfg['table'],'forward']))
    forward=forward_rules(document,cfg)
    phases=[probe(args,names,cfg),probe(args,names,cfg,reverse=True)]
    traffic=all(phase['ping']['status']=='PASS' for phase in phases)
    routed=all(phase['path']['router_path_verified'] for phase in phases)
    status='PASS' if traffic and routed and route_verified and forwarding=='1' and forward['status']=='PASS' else 'FAIL' if any(phase['ping']['status']=='FAIL' for phase in phases) else 'NEEDS_REVIEW'
    gaps=[phase['path']['first_missing_stage'] for phase in phases]
    return {'schema_version':1,'kind':'packet_verification','origin':'live_project_scoped_docker_probe',
        'checked_at':datetime.now(timezone.utc).isoformat(),'profile':profile,'project':cfg['project'],'status':status,
        'networks':networks,'snapshots':snapshots,'selected_routes':selected_routes,'routes_via_router_verified':route_verified,
        'router_ip_forward':forwarding,'forward_rules':forward,'phases':phases,
        'diagnosis':{'first_missing_stages':gaps,'docker_internal_isolation_suspected':profile=='existing' and not traffic and any(gap in ('router_request_in','destination_request_in') for gap in gaps),
                     'exact_docker_host_drop_rule_confirmed':False},
        'configuration_reference':configuration_reference(config_path),
        'limitations':['packet_status_separate_from_R03_R04','no_host_firewall_or_daemon_changes',
                        'shared_L2_fabric_is_not_vlan_isolation' if profile=='fabric' else 'internal_bridge_inter_cidr_filtering_requires_path_evidence',
                        'header_capture_not_payload_capture','host_drop_chain_counters_not_collected']}
