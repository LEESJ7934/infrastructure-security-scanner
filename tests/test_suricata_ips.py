"""Synthetic IPS proof correlation tests. No real network or Docker calls."""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib,io,json,socket,struct,tempfile
from pathlib import Path
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch
from config_audit.collectors import suricata_ips as ips
from scripts.run_suricata_ips import main
from config_audit.ips_execution import Runner,SERVICES,PROJECT,NETWORK

T='2026-11-07T00:00:01+00:00'

def nft(n):
 rows=[{'chain':{'family':'inet','table':'p2ips_guard','name':'forward','type':'filter','hook':'forward','prio':0,'policy':'drop'}}]
 for src,dst,field in [(ips.A,ips.B,'dport'),(ips.B,ips.A,'sport')]:
  expr=[{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':src}},{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':dst}},{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':field}},'right':8080}},{'counter':{'packets':n,'bytes':100*n}},{'queue':{'num':0}}]
  rows.append({'rule':{'family':'inet','table':'p2ips_guard','chain':'forward','expr':expr}})
 return {'nftables':rows}

def packet(src,dst,sport,dport,seq,ttl,uri=None):
 payload=('GET '+uri+' HTTP/1.1\r\n\r\n').encode() if uri else b'HTTP/1.0 200 OK\r\n\r\nresponse'
 return {'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'seq':seq,'ack':0,'flags':24,'ttl':ttl,'payload_size':len(payload),'uri':uri,'timestamp':T}

def sample(phase):
 controls=[{'uri':'/control?run=test-pre','source_port':41001,'status':'HTTP_OK','response_contains_request':True},{'uri':'/control?run=test-post','source_port':41003,'status':'HTTP_OK','response_contains_request':True}]
 marker={'uri':'/ips-lab-marker?run=test','source_port':41002,'status':'HTTP_OK' if phase=='before' else 'TIMEOUT','response_contains_request':phase=='before'}
 sensor={'running':True,'queue0_bound':True,'command':['/usr/bin/suricata','-q','0']}
 nodes={r:{'ready':True,'default_routes':[],'accept_redirects':'0','ip_forward':'1' if r=='gateway' else '0'} for r in ['client','gateway','server']}
 for role,address,gateway in [('client',ips.A,'10.207.10.254'),('server',ips.B,'10.207.20.254')]:
  nodes[role].update(route=[{'gateway':gateway,'dev':'data0'}],addresses=[{'addr_info':[{'local':address,'prefixlen':24}]}])
 captures={n:{'records':[],'complete':True,'kernel_drops':0,'started_at':'2026-11-07T00:00:00+00:00','ended_at':'2026-11-07T00:00:09+00:00'} for n in ['client','gateway','server']}
 events=[]
 for i,request in enumerate([controls[0],marker,controls[1]]):
  sp=request['source_port'];seq=100+i*100
  req=packet(ips.A,ips.B,sp,8080,seq,64,request['uri'])
  for n,d,t in [('client','out',64),('gateway','in',64)]:captures[n]['records'].append({**req,'direction':d,'ttl':t})
  if request is marker and phase=='after':continue
  for n,d,t in [('gateway','out',63),('server','in',63)]:captures[n]['records'].append({**req,'direction':d,'ttl':t})
  response=packet(ips.B,ips.A,8080,sp,seq+10000,64)
  for n,d,t in [('server','out',64),('gateway','in',64),('gateway','out',63),('client','in',63)]:captures[n]['records'].append({**response,'direction':d,'ttl':t})
  events.append({'source':ips.A,'source_port':sp,'uri':request['uri'],'timestamp':T})
 meta={'phase':phase,'scope':{'validated':True,'project':'scanner-p2ips','internal':True},'nodes':nodes,'sensor_before':deepcopy(sensor),'sensor_after':deepcopy(sensor),'nft_before':nft(1),'nft_after':nft(50),'requests':{'controls':controls,'marker':marker},'server_new_events':events}
 eve=[{'timestamp':T,'event_type':'alert','src_ip':ips.A,'dest_ip':ips.B,'src_port':41002,'dest_port':8080,'http':{'url':marker['uri']},'alert':{'signature_id':ips.SID,'rev':1 if phase=='before' else 2,'action':'allowed' if phase=='before' else 'blocked'}}]
 return meta,captures,eve

def pcap(records):
 result=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,1536,1))
 for r in records:
  payload=('GET '+r['uri']+' HTTP/1.1\r\n\r\n').encode() if r['uri'] else b'HTTP/1.0 200 OK\r\n\r\nresponse'
  ip=struct.pack('!BBHHHBBH4s4s',69,0,40+len(payload),0,0,r['ttl'],6,0,socket.inet_aton(r['source']),socket.inet_aton(r['destination']))
  tcp=struct.pack('!HHIIBBHHH',r['source_port'],r['destination_port'],r['seq'],r['ack'],80,r['flags'],65535,0,0)
  frame=b'\0'*12+b'\x08\x00'+ip+tcp+payload;result.extend(struct.pack('<IIII',1,0,len(frame),len(frame))+frame)
 return bytes(result)

class SuricataIPSTests(unittest.TestCase):
 def setUp(self):
  g=patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK'));g.start();self.addCleanup(g.stop)
  self.m,self.c,self.e=sample('after')
 def result(self):return ips.phase_result(self.m,self.c,self.e)
 def test_complete_block_proof(self):self.assertEqual(self.result()['outcome'],'BLOCKED_CONFIRMED')
 def test_alert_is_delivered(self):self.assertEqual(ips.phase_result(*sample('before'))['outcome'],'ALERTED_NOT_BLOCKED')
 def test_normal_allowed_in_both_phases(self):
  for phase in ['before','after']:self.assertEqual(ips.phase_result(*sample(phase))['normal_outcome'],'ALLOWED')
 def test_drop_log_alone_not_proof(self):
  self.c['gateway']['records']=[];self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_process_not_running_no_false_pass(self):self.m['sensor_after']['running']=False;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_queue_listener_missing_no_false_pass(self):self.m['sensor_before']['queue0_bound']=False;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_not_inline_process_no_false_pass(self):self.m['sensor_before']['command']=['suricata','-r','offline.pcap'];self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_route_no_false_block(self):self.m['nodes']['client']['route'][0]['gateway']='10.207.0.1';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_default_route_rejected(self):self.m['nodes']['server']['default_routes']=[{'gateway':'10.207.0.1'}];self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_redirects_rejected(self):self.m['nodes']['server']['accept_redirects']='1';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_forwarding_off_rejected(self):self.m['nodes']['gateway']['ip_forward']='0';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_no_kernel_queue_activity_no_proof(self):self.m['nft_after']=nft(1);self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_queue_bypass_rejected(self):self.m['nft_after']['nftables'][1]['rule']['expr'][-1]['queue']['flags']=['bypass'];self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_extra_accept_rejected(self):self.m['nft_after']['nftables'].append({'rule':{'table':'p2ips_guard','chain':'forward','expr':[{'accept':None}]}});self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_server_received_marker_not_confirmed(self):self.m['server_new_events'].append({'source':ips.A,'source_port':41002,'uri':self.m['requests']['marker']['uri']});self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_server_capture_saw_marker_not_confirmed(self):self.c['server']['records'].append({**self.c['client']['records'][2],'direction':'in'});self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_capture_drop_prevents_absence_proof(self):self.c['server']['kernel_drops']=1;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_capture_incomplete_prevents_absence_proof(self):self.c['gateway']['complete']=False;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_sid_rejected(self):self.e[0]['alert']['signature_id']=42;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_rev_rejected(self):self.e[0]['alert']['rev']=1;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_flow_rejected(self):self.e[0]['src_port']=1;self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_stale_eve_rejected(self):self.e[0]['timestamp']='2020-01-01T00:00:00+00:00';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_uri_rejected(self):self.e[0]['http']['url']='/other';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_control_failure_not_confused_with_block(self):self.m['requests']['controls'][1]['status']='TIMEOUT';self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_wrong_ttl_no_router_proof(self):
  for r in self.c['gateway']['records']:
   if r['direction']=='out':r['ttl']=64
  self.assertEqual(self.result()['outcome'],'NEEDS_REVIEW')
 def test_eve_json_parsing(self):self.assertEqual(ips.parse_eve('\n'.join(json.dumps(e) for e in self.e)),self.e)
 def test_invalid_eve_rejected(self):
  with self.assertRaises(ips.EvidenceError):ips.parse_eve('{bad')
 def test_pcap_matches_metadata(self):self.assertTrue(ips.check_capture(self.c['client'],pcap(self.c['client']['records'])))
 def test_truncated_pcap_rejected(self):
  with self.assertRaises(ips.EvidenceError):ips.pcap_fields(pcap(self.c['client']['records'])[:-1])
 def test_changed_pcap_vs_metadata_rejected(self):
  raw=pcap(self.c['client']['records']);self.c['client']['records'][0]['seq']+=1
  with self.assertRaises(ips.EvidenceError):ips.check_capture(self.c['client'],raw)
 def test_manifest_mutation_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'x.json';p.write_bytes(b'{}');m={'artifacts':[{'file':'x.json','size_bytes':2,'sha256':hashlib.sha256(b'{}').hexdigest()}]}
   self.assertEqual(ips.verify_manifest(tmp,m),{'x.json'});p.write_bytes(b'[]')
   with self.assertRaises(ips.EvidenceError):ips.verify_manifest(tmp,m)
 def test_missing_evidence_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   with self.assertRaises(ips.EvidenceError):ips.verify_manifest(tmp,{'artifacts':[{'file':'missing.json'}]})
 def test_path_escape_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   for ref in ['../x.json','C:\\keys.json','//server/share/x.json','.env.secret','private.key']:
    with self.assertRaises(ips.EvidenceError):ips.verify_manifest(tmp,{'artifacts':[{'file':ref}]})
 def test_duplicate_reference_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'x.json';p.write_bytes(b'{}');r={'file':'x.json','size_bytes':2,'sha256':hashlib.sha256(b'{}').hexdigest()}
   with self.assertRaises(ips.EvidenceError):ips.verify_manifest(tmp,{'artifacts':[r,r]})
 def test_default_cli_does_not_execute(self):
  with patch('subprocess.run',side_effect=AssertionError('NO_DOCKER')),redirect_stdout(io.StringIO()) as out:self.assertEqual(main([]),0)
  self.assertEqual(json.loads(out.getvalue())['status'],'NOT_TESTED')
 def test_synthetic_bundle_uses_existing_evaluate(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);phases={}
   for phase in ['before','after']:
    m,c,e=sample(phase);d=root/phase;d.mkdir();(d/'phase.json').write_text(json.dumps(m));(d/'eve.jsonl').write_text('\n'.join(json.dumps(x) for x in e));refs={'meta':phase+'/phase.json','eve':phase+'/eve.jsonl'}
    for node in ['client','gateway','server']:
     (d/(node+'.json')).write_text(json.dumps(c[node]));(d/(node+'.pcap')).write_bytes(pcap(c[node]['records']));refs[node]=phase+'/'+node+'.json';refs[node+'_pcap']=phase+'/'+node+'.pcap'
    phases[phase]=refs
   (root/'bundle.json').write_text(json.dumps({'schema_version':1,'origin':'synthetic','execution_id':'synthetic-test','suricata_version':'8.0.6','phases':phases,'cleanup':{'restored':True}}))
   manifest={'artifacts':[{'file':p.relative_to(root).as_posix(),'size_bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in root.rglob('*') if p.is_file()]};(root/'manifest.json').write_text(json.dumps(manifest))
   with patch.object(ips,'evaluate',wraps=ips.evaluate) as engine:report=ips.build_report(root)
   self.assertEqual(engine.call_count,6);self.assertEqual(report['origin'],'synthetic');self.assertEqual(report['policy_comparison']['result'],'IMPROVED_OBSERVED')
   self.assertEqual([r['status'] for r in report['policy_comparison']['intended_blocking_results']],['FAIL','PASS']);self.assertTrue(report['policy_comparison']['IDS_detection_itself_is_not_a_vulnerability'])
 def test_new_compose_not_privileged_or_public(self):
  p=Path(__file__).parents[1]/'lab/phase2-ips/compose.json';compose=json.loads(p.read_text());self.assertTrue(compose['networks']['fabric']['internal'])
  for s in compose['services'].values():self.assertFalse(s.get('privileged',False));self.assertNotIn('ports',s);self.assertNotEqual(s.get('network_mode'),'host');self.assertEqual(set(s['cap_add']),{'NET_ADMIN','NET_RAW'})

 def scoped_runner(self):
  r=Runner.__new__(Runner);r.ids={s:'id-'+s for s in SERVICES};r.images={'scanner-p2ips-node:local':'sha-node','scanner-p2ips-sensor:local':'sha-sensor'}
  data={}
  for service in SERVICES:
   h={'Privileged':False,'NetworkMode':'container:id-gateway' if service=='sensor' else NETWORK,'PidMode':'','IpcMode':'private','ReadonlyRootfs':True,'PortBindings':{},'CapAdd':['NET_ADMIN','NET_RAW'],'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']}
   data['id-'+service]={'Id':'id-'+service,'HostConfig':h,'Config':{'Labels':{'com.docker.compose.project':PROJECT,'com.docker.compose.service':service}},'State':{'Running':True},'Image':'sha-sensor' if service=='sensor' else 'sha-node','Mounts':[],'NetworkSettings':{'Networks':{} if service=='sensor' else {NETWORK:{}}}}
  network={'Id':'network-id','Internal':True,'Driver':'bridge','Labels':{'com.docker.compose.project':PROJECT},'IPAM':{'Config':[{'Subnet':'10.207.0.0/16'}]},'Containers':{r.ids[s]:{} for s in ['gateway','client','server']}}
  r.json=lambda *a:[data[a[1]]] if a[0]=='inspect' else [network]
  return r,data,network
 def test_runtime_scope_fixture_valid(self):self.assertTrue(self.scoped_runner()[0].scope()['validated'])
 def test_privileged_container_rejected(self):
  r,d,_=self.scoped_runner();d['id-client']['HostConfig']['Privileged']=True
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_host_network_rejected(self):
  r,d,_=self.scoped_runner();d['id-client']['HostConfig']['NetworkMode']='host'
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_sensor_foreign_namespace_rejected(self):
  r,d,_=self.scoped_runner();d['id-sensor']['HostConfig']['NetworkMode']='container:other'
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_public_port_rejected(self):
  r,d,_=self.scoped_runner();d['id-client']['HostConfig']['PortBindings']={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8080'}]}
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_foreign_network_endpoint_rejected(self):
  r,_,n=self.scoped_runner();n['Containers']['foreign']={}
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_additional_capability_rejected(self):
  r,d,_=self.scoped_runner();d['id-sensor']['HostConfig']['CapAdd'].append('SYS_ADMIN')
  with self.assertRaises(ips.EvidenceError):r.scope()
 def test_null_ipam_config_preflight_safe(self):
  r=Runner.__new__(Runner);r.images={};r.inventory=lambda:{};r.save=lambda *a:None
  r.text=lambda *a:'linux' if a[0]=='info' else 'host none' if a[0]=='network' else 'sha-base'
  r.json=lambda *a:[{'Name':'host','IPAM':{'Config':None}},{'Name':'none','IPAM':{'Config':None}}]
  r.preflight();self.assertEqual(len(r.images),2)
 def test_preflight_overlap_rejected(self):
  r=Runner.__new__(Runner);r.images={};r.inventory=lambda:{};r.save=lambda *a:None
  r.text=lambda *a:'linux' if a[0]=='info' else 'existing'
  r.json=lambda *a:[{'Name':'existing','IPAM':{'Config':[{'Subnet':'10.207.10.0/24'}]}}]
  with self.assertRaises(ips.EvidenceError):r.preflight()

class FailureAndCleanupTests(unittest.TestCase):
 def test_inventory_network_order_not_a_change(self):
  from config_audit.ips_execution import same_inventory
  self.assertTrue(same_inventory({'r':{'id':'1','networks':'a,b'}},{'r':{'id':'1','networks':'b,a'}}))
  self.assertFalse(same_inventory({'r':{'id':'1','networks':'a,b'}},{'r':{'id':'1','networks':'a,c'}}))

 def test_failed_deployment_is_not_packet_success(self):
  report=ips.failure_report('run','nfqueue_kernel_unavailable','deploy',{'restored':True})
  self.assertEqual([r['status'] for r in report['results']],['ERROR','NOT_TESTED','NOT_TESTED','NOT_TESTED','PASS'])
  self.assertEqual(report['policy_comparison']['result'],'UNVERIFIABLE');self.assertEqual(report['phases'],[])
 def test_unverified_cleanup_is_not_pass(self):
  self.assertEqual(ips.failure_report('run','unavailable','deploy',{'restored':False})['results'][-1]['status'],'NOT_TESTED')
 def test_partial_stopped_gateway_cleanup(self):
  from types import SimpleNamespace
  r=Runner.__new__(Runner);r.created=True;r.ids={};r.phases={};r.original_inventory={'old':{'id':'old','networks':'oldnet'}}
  r.save=lambda *a:None;r.sensor=lambda *a:{'running':False}
  def call(*args,**kw):
   if args[0]=='inspect':
    role=args[1].split('-')[-2]
    data=[{'Id':'id-'+role,'Config':{'Labels':{'com.docker.compose.project':PROJECT,'com.docker.compose.service':role}},'State':{'Running':role!='gateway'}}]
   else:data=[{'Containers':{}}]
   return SimpleNamespace(returncode=0,stdout=json.dumps(data).encode(),stderr=b'')
  r.call=call;r.compose=lambda *a,**kw:SimpleNamespace(stdout=b'',stderr=b'');r.inventory=lambda:r.original_inventory;r.text=lambda *a:''
  def inspect_tables(role,*args):
   self.assertNotEqual(role,'gateway');return {'nftables':[]}
  r.exec_json=inspect_tables
  self.assertTrue(r.cleanup()['restored'])
 def test_cleanup_foreign_identity_refuses_deletion(self):
  from types import SimpleNamespace
  r=Runner.__new__(Runner);r.created=True;r.ids={};r.save=lambda *a:None
  r.call=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':'foreign','Config':{'Labels':{}}}]).encode())
  r.compose=lambda *a,**kw:self.fail('foreign project deletion')
  self.assertEqual(r.cleanup()['error_code'],'cleanup_foreign_container')

if __name__=='__main__':unittest.main()
