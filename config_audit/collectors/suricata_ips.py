"""Correlate IPS evidence with the existing audit engine; never treats DROP alone as proof."""
from datetime import datetime,timezone
import hashlib,json,re,struct,socket
from pathlib import Path,PureWindowsPath
from ..models import AuditAsset,AuditRule,Observation
from ..engine import evaluate

A='10.207.10.10';B='10.207.20.10';PORT=8080;SID=1000701;VERSION='IPS-LAB-0.1'
class EvidenceError(ValueError):pass

def need(value,code):
 if not value:raise EvidenceError(code)

def read_json(path):
 try:return json.loads(Path(path).read_text(encoding='utf-8-sig'))
 except (OSError,ValueError):raise EvidenceError('evidence_json_invalid') from None

def verify_manifest(root,document):
 root=Path(root).resolve();need(isinstance(document,dict) and isinstance(document.get('artifacts'),list),'manifest_invalid');seen=set()
 for row in document['artifacts']:
  ref=row.get('file');need(isinstance(ref,str) and ref not in seen,'duplicate_or_invalid_reference');seen.add(ref)
  p=Path(ref);need(not p.is_absolute() and not PureWindowsPath(ref).drive and '\\' not in ref and '..' not in p.parts and not any(part.lower() in ('.git','.aws') or part.lower().startswith('.env') for part in p.parts) and p.suffix.lower() not in ('.pem','.key','.pfx','.p12'),'unsafe_evidence_reference')
  target=root/p
  need(root in target.resolve().parents and not target.is_symlink() and all(not a.is_symlink() for a in target.parents if a!=root),'unsafe_evidence_reference')
  need(target.is_file(),'evidence_missing');raw=target.read_bytes();need(len(raw)<=4*1024*1024,'evidence_size_limit')
  need(len(raw)==row.get('size_bytes') and hashlib.sha256(raw).hexdigest()==row.get('sha256'),'evidence_hash_mismatch')
 return seen

def parse_eve(text):
 events=[]
 for line in text.splitlines():
  if not line.strip():continue
  try:value=json.loads(line)
  except ValueError:raise EvidenceError('eve_parse_failed') from None
  need(isinstance(value,dict) and isinstance(value.get('event_type'),str),'eve_event_invalid')
  if value['event_type']=='alert':need(isinstance(value.get('alert'),dict) and type(value['alert'].get('signature_id')) is int,'eve_alert_invalid')
  events.append(value)
 return events

def pcap_fields(raw):
 need(len(raw)>=24 and raw[:4]==b'\xd4\xc3\xb2\xa1' and struct.unpack('<I',raw[20:24])[0]==1,'pcap_header_invalid');offset=24;result=[]
 while offset<len(raw):
  need(len(raw)-offset>=16,'pcap_truncated');_,_,length,original=struct.unpack('<IIII',raw[offset:offset+16]);offset+=16
  need(54<=length<=1536 and original==length and offset+length<=len(raw),'pcap_truncated');frame=raw[offset:offset+length];offset+=length
  need(frame[12:14]==b'\x08\x00','pcap_outside_scope');ip=frame[14:];ihl=(ip[0]&15)*4
  need(ip[9]==6 and ihl>=20 and len(ip)>=ihl+20,'pcap_outside_scope');tcp=ip[ihl:];sport,dport,seq,ack=struct.unpack('!HHII',tcp[:12]);thl=(tcp[12]>>4)*4
  src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20]);need((src,dst) in ((A,B),(B,A)) and PORT in (sport,dport),'pcap_outside_scope')
  payload=tcp[thl:];m=re.search(rb'GET (/[^ \r\n]{1,160}) HTTP/1\.[01]',payload)
  result.append({'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'seq':seq,'ack':ack,'flags':tcp[13],'ttl':ip[8],'payload_size':len(payload),'uri':m[1].decode('ascii','replace') if m else None})
 return result

def check_capture(meta,pcap):
 need(isinstance(meta.get('records'),list),'capture_invalid');decoded=pcap_fields(pcap);need(len(decoded)==len(meta['records']),'capture_pcap_mismatch')
 for a,b in zip(decoded,meta['records']):need(all(b.get(k)==v for k,v in a.items()),'capture_pcap_mismatch')
 return meta.get('complete') is True and meta.get('kernel_drops')==0

def queue_config(nft):
 rows=nft.get('nftables',[]);chains=[r['chain'] for r in rows if isinstance(r.get('chain'),dict) and r['chain'].get('table')=='p2ips_guard' and r['chain'].get('name')=='forward']
 if len(chains)!=1 or chains[0].get('policy')!='drop' or chains[0].get('hook')!='forward':return False,0
 rules=[r['rule'] for r in rows if isinstance(r.get('rule'),dict) and r['rule'].get('table')=='p2ips_guard' and r['rule'].get('chain')=='forward'];seen=set();packets=0
 for r in rules:
  fields={};queue=None
  for e in r.get('expr',[]):
   if 'counter' in e:packets+=e['counter'].get('packets',0)
   elif 'queue' in e:queue=e['queue']
   elif 'match' in e:
    m=e['match'];left=m.get('left',{}).get('payload',{});
    if m.get('op')!='==':return False,packets
    fields[(left.get('protocol'),left.get('field'))]=m.get('right')
   else:return False,packets
  if not isinstance(queue,dict) or queue.get('num')!=0 or queue.get('flags'):return False,packets
  if fields=={('ip','saddr'):A,('ip','daddr'):B,('tcp','dport'):PORT}:seen.add('request')
  elif fields=={('ip','saddr'):B,('ip','daddr'):A,('tcp','sport'):PORT}:seen.add('response')
  else:return False,packets
 return len(rules)==2 and seen=={'request','response'},packets

def topology(meta):
 scope=meta.get('scope',{})
 if not(scope.get('validated') is True and scope.get('project')=='scanner-p2ips' and scope.get('internal') is True):return False
 nodes=meta.get('nodes',{})
 for role in ('client','server','gateway'):
  n=nodes.get(role,{})
  if n.get('default_routes')!=[] or n.get('accept_redirects')!='0' or n.get('ready') is not True:return False
 if nodes['gateway'].get('ip_forward')!='1':return False
 for role,gateway in [('client','10.207.10.254'),('server','10.207.20.254')]:
  routes=nodes[role].get('route',[])
  if len(routes)!=1 or routes[0].get('gateway')!=gateway or routes[0].get('dev')!='data0':return False
  expected=A if role=='client' else B
  if not any(a.get('local')==expected and a.get('prefixlen')==24 for interface in nodes[role].get('addresses',[]) for a in interface.get('addr_info',[])):return False
 return True

def process_live(info):
 cmd=info.get('command',[])
 return info.get('running') is True and info.get('queue0_bound') is True and '/usr/bin/suricata' in cmd and '-q' in cmd and cmd[cmd.index('-q')+1:cmd.index('-q')+2]==['0']

def packet_path(captures,request):
 port=request.get('source_port');uri=request.get('uri')
 def packets(node,direction,src,dst,query=False):
  return [e for e in captures[node]['records'] if e.get('direction')==direction and e.get('source')==src and e.get('destination')==dst and (e.get('source_port')==port if src==A else e.get('destination_port')==port) and (e.get('uri')==uri if query else e.get('payload_size',0)>0)]
 ao=packets('client','out',A,B,True);gi=packets('gateway','in',A,B,True);go=packets('gateway','out',A,B,True);si=packets('server','in',A,B,True)
 so=packets('server','out',B,A);ri=packets('gateway','in',B,A);ro=packets('gateway','out',B,A);ai=packets('client','in',B,A)
 def hop(first,last):return any(x['seq']==y['seq'] and x['ttl']==y['ttl']+1 for x in first for y in last)
 def same(first,last):return any(x['seq']==y['seq'] and x['ttl']==y['ttl'] for x in first for y in last)
 incoming=bool(ao and gi and same(ao,gi))
 routed=bool(incoming and go and si and hop(gi,go) and same(go,si) and so and ri and ro and ai and same(so,ri) and hop(ri,ro) and same(ro,ai))
 return {'ingress_verified':incoming,'bidirectional_router_path':routed,'gateway_request_out':len(go),'server_request_in':len(si)}

def phase_result(meta,captures,events):
 need(meta.get('phase') in ('before','after'),'phase_invalid');phase=meta['phase'];requests=meta['requests'];marker=requests['marker']
 source_ok=topology(meta) and process_live(meta.get('sensor_before',{})) and process_live(meta.get('sensor_after',{}))
 q0,n0=queue_config(meta.get('nft_before',{}));q1,n1=queue_config(meta.get('nft_after',{}));source_ok &= q0 and q1 and n1>n0
 source_ok &= all(captures[n].get('complete') is True and captures[n].get('kernel_drops')==0 for n in ('client','gateway','server'))
 def delivered(request):return any(e.get('uri')==request['uri'] and e.get('source_port')==request['source_port'] and e.get('source')==A for e in meta.get('server_new_events',[]))
 controls=requests['controls'];control_ok=len(controls)==2 and all(r.get('status')=='HTTP_OK' and r.get('response_contains_request') is True and delivered(r) and packet_path(captures,r)['bidirectional_router_path'] for r in controls)
 path=packet_path(captures,marker);matches=[]
 for e in events:
  if e.get('event_type')!='alert':continue
  a=e['alert']
  if a.get('signature_id')!=SID or a.get('rev')!=(1 if phase=='before' else 2):continue
  if (e.get('src_ip'),e.get('dest_ip'),e.get('src_port'),e.get('dest_port'))!=(A,B,marker.get('source_port'),PORT):continue
  if e.get('http',{}).get('url') not in (None,marker['uri']):continue
  try:
   t=datetime.fromisoformat(e['timestamp']);lo=min(datetime.fromisoformat(c['started_at']) for c in captures.values());hi=max(datetime.fromisoformat(c['ended_at']) for c in captures.values())
   if t.utcoffset() is None or not lo<=t<=hi:continue
  except (ValueError,TypeError,KeyError):continue
  matches.append(e)
 allowed=source_ok and control_ok and marker.get('status')=='HTTP_OK' and marker.get('response_contains_request') is True and delivered(marker) and path['bidirectional_router_path'] and any(e['alert'].get('action')=='allowed' for e in matches)
 blocked=source_ok and control_ok and marker.get('status') in ('TIMEOUT','RESET') and not delivered(marker) and path['ingress_verified'] and path['gateway_request_out']==path['server_request_in']==0 and any(e['alert'].get('action')=='blocked' for e in matches)
 outcome='ALERTED_NOT_BLOCKED' if allowed else 'BLOCKED_CONFIRMED' if blocked else 'NEEDS_REVIEW'
 return {'phase':phase,'outcome':outcome,'normal_outcome':'ALLOWED' if source_ok and control_ok else 'NEEDS_REVIEW','inline_and_path_evidence':bool(source_ok),
         'marker_delivered_to_server':delivered(marker),'marker_client_status':marker.get('status'),'path':path,'matched_alert_count':len(matches),'sid':SID,'revision':1 if phase=='before' else 2,
         'blocking_observed':True if blocked else False if allowed else None,'control_verified':bool(control_ok)}

def build_report(root):
 root=Path(root);manifest=read_json(root/'manifest.json');known=verify_manifest(root,manifest);need('bundle.json' in known,'bundle_not_indexed');bundle=read_json(root/'bundle.json')
 need(bundle.get('schema_version')==1 and bundle.get('origin') in ('docker_live','synthetic'),'bundle_invalid')
 phases=[]
 for phase in ('before','after'):
  refs=bundle['phases'][phase];need(set(refs.values())<=known,'unindexed_evidence_reference');meta=read_json(root/refs['meta']);captures={}
  for node in ('client','gateway','server'):
   c=read_json(root/refs[node]);check_capture(c,(root/refs[node+'_pcap']).read_bytes());captures[node]=c
  events=parse_eve((root/refs['eve']).read_text());phases.append(phase_result(meta,captures,events))
 before,after=phases;now=datetime.now(timezone.utc);execution=bundle['execution_id'];asset=AuditAsset('lab/scanner-p2ips/sensor','suricata',bundle.get('suricata_version'))
 results=[]
 facts=[('IPS-LAB-001','Normal traffic allowed through IPS in both phases',all(p['normal_outcome']=='ALLOWED' for p in phases)),
        ('IPS-LAB-002','Alert-only marker detected and delivered',True if before['outcome']=='ALERTED_NOT_BLOCKED' else None),
        ('IPS-LAB-003','Marker actually blocked by inline Suricata',True if after['outcome']=='BLOCKED_CONFIRMED' else None),
        ('IPS-LAB-004','Temporary namespace rules removed and unrelated LABs preserved',bundle.get('cleanup',{}).get('restored') is True)]
 for check,title,value in facts:
  rule=AuditRule(check,VERSION,title,'Review scoped process, EVE, PCAP, client and server evidence.',condition=lambda v:v,product='suricata')
  result=evaluate(asset,rule,Observation(value,'manifest.json'),execution_id=execution,checked_at=now)
  results.append({**result.to_safe_dict(),'evidence_reference':'manifest.json','expected_condition':title})
 policy=AuditRule('IPS-LAB-POLICY',VERSION,'Intended marker-blocking policy enforced','Use drop only inside the isolated LAB.',condition=lambda v:v)
 policy_results=[]
 for phase in phases:
  r=evaluate(asset,policy,Observation(phase['blocking_observed'],'manifest.json'),execution_id=execution,checked_at=now)
  policy_results.append({**r.to_safe_dict(),'phase':phase['phase']})
 improved=before['outcome']=='ALERTED_NOT_BLOCKED' and after['outcome']=='BLOCKED_CONFIRMED'
 return {'schema_version':1,'execution_id':execution,'origin':bundle['origin'],'generated_at':now.isoformat(),'asset_id':asset.asset_id,'suricata_version':asset.version,'method':'Linux NFQUEUE queue 0',
  'phases':phases,'results':results,'policy_comparison':{'result':'IMPROVED_OBSERVED' if improved else 'UNVERIFIABLE','intended_blocking_results':policy_results,'IDS_detection_itself_is_not_a_vulnerability':True},
  'cleanup':bundle.get('cleanup'),'limitations':['OPNsense_IPS_NOT_TESTED','LAB_TCP_HTTP_scope_only','hash_match_not_independent_source_authentication','alert_vs_drop_are_different_expected_behaviors'],
  'evidence':{'manifest':'manifest.json','independently_verified':False,'artifact_count':len(known)}}

def write_pdf(report,destination):
 from api.report_pdf import _body_font,_text
 from reportlab.lib.styles import ParagraphStyle
 from reportlab.platypus import SimpleDocTemplate,Paragraph,Table,TableStyle,Spacer
 from reportlab.lib import colors
 font=_body_font();body=ParagraphStyle('ips',fontName=font,fontSize=10,leading=15,wordWrap='CJK');head=ParagraphStyle('head',parent=body,fontSize=17,leading=22,spaceAfter=12)
 p=lambda value:Paragraph(_text(str(value)),body)
 story=[Paragraph('Suricata inline IPS LAB verification',head),p('Origin: '+report['origin']),p('Execution: '+report['execution_id']),p('Suricata '+str(report['suricata_version'])+' | '+report['method'])]
 rows=[[p('Phase'),p('Control'),p('Marker'),p('Evidence')]]
 for phase in report['phases']:rows.append([p(phase['phase']),p(phase['normal_outcome']),p(phase['outcome']),p(str(phase['path']))])
 table=Table(rows,colWidths=[55,85,135,235]);table.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.4,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.lightgrey)]));story.extend([Spacer(1,12),table,p('Policy comparison: '+report['policy_comparison']['result']),p('IDS detection is expected behavior; the comparison concerns intended blocking policy only.'),p('Cleanup: '+str(report['cleanup']))])
 for row in report['results']:story.append(p(row['check_id']+' '+row['status']+' - '+row['expected_condition']))
 for limitation in report['limitations']:story.append(p(limitation))
 story.append(p('Evidence: scoped EVE, client/server events, node captures and PCAP hashes are linked by manifest.json. Independently verified: false.' if report['phases'] else 'Startup failed before packet tests. No EVE or PCAP blocking evidence exists. See kernel-capability.json and syntax-validation.json. Hashes are self-computed, not independently authenticated.'))
 with Path(destination).open('xb') as stream:SimpleDocTemplate(stream,leftMargin=40,rightMargin=40,topMargin=40,bottomMargin=40).build(story)


def failure_report(execution_id,error,stage,cleanup):
 """A failed deployment is not packet-blocking evidence. No invented captures."""
 now=datetime.now(timezone.utc);asset=AuditAsset('lab/scanner-p2ips/sensor','suricata',None)
 results=[]
 for check,title,value,failed in [('IPS-LAB-000','Inline startup completed',None,True),('IPS-LAB-001','Normal traffic allowed through IPS',None,False),('IPS-LAB-002','Alert marker detected and delivered',None,False),('IPS-LAB-003','Marker actually blocked',None,False),('IPS-LAB-004','New namespaces removed and existing containers preserved',True if cleanup.get('restored') else None,False)]:
  rule=AuditRule(check,VERSION,title,'Resolve scoped startup failure and repeat in an explicitly supported isolated kernel.',condition=lambda v:v)
  row=evaluate(asset,rule,Observation(value,'failure.json',collection_error=failed),execution_id=execution_id,checked_at=now)
  results.append({**row.to_safe_dict(),'expected_condition':title,'reason':error if failed else 'packet_tests_not_performed' if value is None else 'cleanup_verified','evidence_reference':'failure.json'})
 return {'schema_version':1,'execution_id':execution_id,'origin':'docker_live','generated_at':now.isoformat(),'asset_id':asset.asset_id,'suricata_version':'8.0.6 (image capability only; IPS process not verified)','method':'Linux NFQUEUE queue 0','phases':[], 'results':results,'failure':{'error_code':error,'stage':stage},'policy_comparison':{'result':'UNVERIFIABLE','intended_blocking_results':[],'IDS_detection_itself_is_not_a_vulnerability':True},'cleanup':cleanup,'limitations':['INLINE_BLOCKING_NOT_CONFIRMED','no_packet_tests_EVE_or_PCAP_collected','OPNsense_IPS_NOT_TESTED','self_computed_hash_not_source_authentication'],'evidence':{'independently_verified':False}}
