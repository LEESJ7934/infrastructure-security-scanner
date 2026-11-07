"""Provision/verify/restore ONLY scanner-p2ips. Local Docker Desktop pipe only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import base64,hashlib,ipaddress,json,os,subprocess,time
from pathlib import Path
from uuid import uuid4
from .collectors.suricata_ips import EvidenceError,need,build_report,write_pdf,topology,queue_config,phase_result,parse_eve,check_capture,failure_report

PROJECT='scanner-p2ips';NETWORK=PROJECT+'_fabric'
DOCKER=['docker','--host','npipe:////./pipe/dockerDesktopLinuxEngine']
ROOT=Path(__file__).resolve().parents[1];LAB=ROOT/'lab/phase2-ips'
SERVICES=('gateway','client','server','sensor')

def now():return datetime.now(timezone.utc).isoformat()

def same_inventory(before,after):
 def normalized(items):return {name:{**v,'networks':sorted(v['networks'].split(','))} for name,v in items.items()}
 return normalized(before)==normalized(after)

class Runner:
 def __init__(self,root):
  parent=Path(root).resolve();need((ROOT/'reports').resolve() in parent.parents or parent==(ROOT/'reports').resolve(),'output_reports_only')
  parent.mkdir(parents=True,exist_ok=True);self.path=parent/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex);self.path.mkdir()
  self.execution_id=uuid4().hex;self.created=False;self.ids={};self.images={};self.phases={};self.original_inventory=None
 def call(self,*args,input=None,timeout=30,allow=False):
  env={k:v for k,v in os.environ.items() if k.upper() not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'}}
  try:r=subprocess.run([*DOCKER,*args],input=input,capture_output=True,timeout=timeout,env=env)
  except (OSError,subprocess.TimeoutExpired):raise EvidenceError('docker_unavailable_or_timeout') from None
  if r.returncode and not allow:
   self.save('last-error.txt',r.stderr[:32768]);raise EvidenceError('docker_command_failed')
  return r
 def text(self,*args,**kw):return self.call(*args,**kw).stdout.decode('utf-8','replace')
 def json(self,*args,**kw):
  try:return json.loads(self.text(*args,**kw))
  except ValueError:raise EvidenceError('docker_response_invalid') from None
 def save(self,relative,value):
  path=self.path/relative;path.parent.mkdir(parents=True,exist_ok=True)
  if isinstance(value,bytes):
   with path.open('xb') as f:f.write(value)
  else:
   with path.open('x',encoding='utf-8') as f:f.write(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2))
  return relative
 def inventory(self):
  lines=self.text('ps','-a','--format','{{.ID}}|{{.Names}}|{{.Networks}}').splitlines()
  return {line.split('|')[1]:{'id':line.split('|')[0],'networks':line.split('|')[2]} for line in lines}
 def preflight(self):
  need(self.text('info','--format','{{.OSType}}').strip()=='linux','linux_engine_required')
  self.original_inventory=self.inventory();need(not any(name.startswith(PROJECT+'-') for name in self.original_inventory),'existing_IPS_lab_rejected')
  network_ids=self.text('network','ls','-q').split()
  for n in self.json('network','inspect',*network_ids):
   need(n['Name']!=NETWORK,'existing_IPS_network_rejected')
   for config in n.get('IPAM',{}).get('Config') or []:
    if config.get('Subnet') and ipaddress.ip_network(config['Subnet']).version==4:need(not ipaddress.ip_network('10.207.0.0/16').overlaps(ipaddress.ip_network(config['Subnet'])),'network_overlap_rejected')
  for tag in ('scanner-p2net:local','jasonish/suricata:8.0.6'):self.images[tag]=self.text('image','inspect',tag,'--format','{{.Id}}').strip()
  self.save('inputs/previous-containers.json',self.original_inventory)
  for p in LAB.iterdir():
   if p.is_file():self.save('inputs/'+p.name,p.read_bytes())
 def compose(self,*args,**kw):return self.call('compose','-f',str(LAB/'compose.json'),*args,**kw)
 def deploy(self):
  built=self.compose('build',timeout=180);self.save('build.txt',built.stdout+built.stderr)
  self.created=True
  up=self.compose('up','-d','--no-build',timeout=90);self.save('startup.txt',up.stdout+up.stderr)
  for service in SERVICES:
   name=PROJECT+'-'+service+'-1';info=self.json('inspect',name)[0]
   need(info.get('Config',{}).get('Labels',{}).get('com.docker.compose.project')==PROJECT,'foreign_container_rejected');self.ids[service]=info['Id']
  for tag in ('scanner-p2ips-node:local','scanner-p2ips-sensor:local'):self.images[tag]=self.text('image','inspect',tag,'--format','{{.Id}}').strip()
  for _ in range(30):
   try:
    self.scope();nodes=self.nodes()
    if all(n.get('ready') is True for n in nodes.values()):break
   except EvidenceError:pass
   time.sleep(.2)
  try:self.scope()
  except EvidenceError:
   logs=self.call('logs','--tail','50',self.ids['gateway'],allow=True)
   self.save('gateway-startup.txt',logs.stdout+logs.stderr)
   if b'NFQUEUE_KERNEL_UNAVAILABLE' in logs.stdout+logs.stderr:raise EvidenceError('nfqueue_kernel_unavailable') from None
   raise
  for tag in ('scanner-p2net:local','jasonish/suricata:8.0.6'):need(self.text('image','inspect',tag,'--format','{{.Id}}').strip()==self.images[tag],'base_image_changed')
  self.save('inputs/images.json',self.images)
  version=self.exec_text('sensor','/usr/bin/suricata','-V').strip();need('8.0.6' in version,'unexpected_suricata_version');self.version='8.0.6'
  self.save('inputs/build-info.txt',self.exec_text('sensor','/usr/bin/suricata','--build-info'))
  need('NFQueue support:                       yes' in (self.path/'inputs/build-info.txt').read_text(),'NFQUEUE_build_not_supported')
  for name in ['suricata.yaml','alert.rules','drop.rules','classification.config','reference.config']:
   actual=self.exec_raw('sensor','cat','/opt/ips/'+name)
   need(actual==(LAB/name).read_bytes(),'image_source_mismatch')
 def scope(self):
  for service in SERVICES:
   info=self.json('inspect',self.ids[service])[0];host=info['HostConfig'];labels=info['Config']['Labels']
   need(info['Id']==self.ids[service] and labels.get('com.docker.compose.project')==PROJECT and labels.get('com.docker.compose.service')==service and info['State']['Running'],'unsafe_container_identity')
   need(not host['Privileged'] and host.get('NetworkMode')!='host' and host.get('PidMode')!='host' and host.get('IpcMode')!='host' and host.get('ReadonlyRootfs') is True,'unsafe_namespace')
   need(not any((host.get('PortBindings') or {}).values()),'published_ports_rejected')
   need(set(x.removeprefix('CAP_') for x in host.get('CapAdd') or [])=={'NET_ADMIN','NET_RAW'} and 'ALL' in (host.get('CapDrop') or []),'capability_scope_rejected')
   need(any(x.startswith('no-new-privileges') for x in host.get('SecurityOpt') or []),'privilege_guard_missing')
   need(all(m.get('Type')=='tmpfs' and m.get('Destination')=='/tmp' for m in info.get('Mounts',[])),'mount_rejected')
   expected='scanner-p2ips-sensor:local' if service=='sensor' else 'scanner-p2ips-node:local'
   need(info['Image']==self.images.get(expected),'image_changed')
   if service=='sensor':need(host['NetworkMode']=='container:'+self.ids['gateway'],'sensor_network_namespace_rejected')
   else:need(set(info['NetworkSettings']['Networks'])=={NETWORK},'external_network_rejected')
  network=self.json('network','inspect',NETWORK)[0]
  need(network['Internal'] is True and network['Driver']=='bridge' and network['Labels'].get('com.docker.compose.project')==PROJECT,'network_scope_rejected')
  need([v.get('Subnet') for v in network['IPAM']['Config']]==['10.207.0.0/16'],'subnet_scope_rejected')
  need(set(network.get('Containers',{}))=={self.ids[s] for s in ('gateway','client','server')},'foreign_network_endpoint')
  return {'validated':True,'project':PROJECT,'internal':True,'network_id':network['Id'],'container_ids':self.ids.copy(),'images':self.images.copy()}
 def exec_raw(self,service,*args):
  need(service in self.ids,'unowned_container');return self.call('exec',self.ids[service],*args).stdout
 def exec_text(self,service,*args):return self.exec_raw(service,*args).decode('utf-8','replace')
 def exec_json(self,service,*args):
  try:return json.loads(self.exec_text(service,*args))
  except ValueError:raise EvidenceError('container_response_invalid') from None
 def nodes(self):return {s:self.exec_json(s,'python3','-B','/opt/ips/probe.py','status') for s in ('gateway','client','server')}
 def sensor(self,*args):return self.exec_json('sensor','/usr/bin/python3','-B','/opt/ips/sensor.py',*args)
 def request(self,uri):return self.exec_json('client','python3','-B','/opt/ips/probe.py','request',uri)
 def phase(self,phase):
  scope=self.scope();nodes=self.nodes()
  need(topology({'scope':scope,'nodes':nodes}) and queue_config(nodes['gateway']['nft'])[0],'routing_or_queue_scope_invalid')
  started=self.sensor('start',phase)
  self.save(phase+'/sensor-start.json',started);need(started.get('validation_exit')==0 and started.get('start_exit')==0 and started.get('running') and started.get('queue0_bound'),'sensor_start_failed')
  sensor_before=self.sensor('status');server_before=nodes['server']['server_events'];nft_before=nodes['gateway']['nft']
  captures={}
  env={k:v for k,v in os.environ.items() if k.upper() not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'}}
  for node in ('client','gateway','server'):
   p=subprocess.Popen([*DOCKER,'exec','-i',self.ids[node],'python3','-B','/opt/ips/probe.py','capture'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',env=env)
   # A bounded ready future avoids hanging if AF_PACKET is unavailable.
   with ThreadPoolExecutor(max_workers=1) as pool:
    future=pool.submit(p.stdout.readline)
    try:ready=json.loads(future.result(timeout=8))
    except Exception:p.kill();raise EvidenceError('capture_not_ready') from None
   need(ready.get('ready') is True,'capture_not_ready');captures[node]=p
  for p in captures.values():p.stdin.write('GO\n');p.stdin.flush()
  marker='/ips-lab-marker?run='+self.execution_id
  control1=self.request('/control?run='+self.execution_id+'-'+phase+'-pre')
  mark=self.request(marker)
  control2=self.request('/control?run='+self.execution_id+'-'+phase+'-post')
  refs={}
  for node,p in captures.items():
   p.stdin.close();p.stdin=None
   try:stdout,stderr=p.communicate(timeout=15)
   except subprocess.TimeoutExpired:p.kill();raise EvidenceError('capture_timeout') from None
   need(p.returncode==0,'capture_process_failed')
   try:c=json.loads(stdout)
   except ValueError:raise EvidenceError('capture_json_invalid') from None
   pcap=base64.b64decode(c.pop('pcap_base64'),validate=True)
   refs[node]=self.save(phase+'/'+node+'-capture.json',c);refs[node+'_pcap']=self.save(phase+'/'+node+'.pcap',pcap)
  sensor_after=self.sensor('status');nft_after=self.nodes()['gateway']['nft'];events=self.exec_json('server','python3','-B','/opt/ips/probe.py','status')['server_events']
  need(events[:len(server_before)]==server_before,'server_ledger_changed')
  stopped=self.sensor('stop');need(not stopped['running'],'sensor_stop_failed')
  refs['eve']=self.save(phase+'/eve.jsonl',self.exec_raw('sensor','/usr/bin/python3','/opt/ips/sensor.py','read',phase,'eve.json'))
  for name in ('validation.txt','startup.txt','suricata.log'):
   self.save(phase+'/'+name,self.exec_raw('sensor','/usr/bin/python3','/opt/ips/sensor.py','read',phase,name))
  meta={'phase':phase,'execution_id':self.execution_id,'scope':scope,'nodes':nodes,'sensor_before':sensor_before,'sensor_after':sensor_after,'nft_before':nft_before,'nft_after':nft_after,
   'requests':{'controls':[control1,control2],'marker':mark},'server_pre_count':len(server_before),'server_new_events':events[len(server_before):],
   'rule_sid':1000701,'rule_rev':1 if phase=='before' else 2,'rule_action':'alert' if phase=='before' else 'drop','started':started,'sensor_stopped':stopped}
  refs['meta']=self.save(phase+'/phase.json',meta);self.phases[phase]=refs
  decoded={}
  for node in ('client','gateway','server'):
   decoded[node]=json.loads((self.path/refs[node]).read_text())
   check_capture(decoded[node],(self.path/refs[node+'_pcap']).read_bytes())
  verdict=phase_result(meta,decoded,parse_eve((self.path/refs['eve']).read_text()))
  self.save(phase+'/verdict.json',verdict)
  need(verdict['outcome']==('ALERTED_NOT_BLOCKED' if phase=='before' else 'BLOCKED_CONFIRMED'),'phase_evidence_not_confirmed')
 def cleanup(self):
  result={'restored':False,'temporary_tables_removed':False,'new_namespaces_removed':False,'unrelated_containers_preserved':False}
  if not self.created:return result
  try:
   # Validate labels/names before any deletion. No foreign namespace is touched.
   running={}
   for service in SERVICES:
    name=PROJECT+'-'+service+'-1';r=self.call('inspect',name,allow=True)
    if r.returncode==0:
     i=json.loads(r.stdout)[0];need(i['Config']['Labels'].get('com.docker.compose.project')==PROJECT and i['Config']['Labels'].get('com.docker.compose.service')==service,'cleanup_foreign_container')
     need(not self.ids.get(service) or self.ids[service]==i['Id'],'cleanup_id_changed');self.ids[service]=i['Id'];running[service]=i['State']['Running']
   if running.get('sensor'):self.sensor('stop')
   tables_removed=True
   for role in ('gateway','client','server'):
    if not running.get(role):continue
    table='p2ips_guard' if role=='gateway' else 'p2ips_endpoint'
    tables=self.exec_json(role,'nft','-j','list','tables')
    if any(x.get('table',{}).get('name')==table for x in tables.get('nftables',[])):self.exec_raw(role,'nft','delete','table','inet',table)
    after=self.exec_json(role,'nft','-j','list','tables');tables_removed &= not any(x.get('table',{}).get('name')==table for x in after.get('nftables',[]))
   result['temporary_tables_removed']=tables_removed
   result['stopped_namespaces_pending_removal']=[s for s in self.ids if not running.get(s)]
   if len(self.phases)==2:
    r=self.request('/control?run='+self.execution_id+'-restored');result['post_rule_removal_control']=r
   network=self.call('network','inspect',NETWORK,allow=True)
   if network.returncode==0:need(set(json.loads(network.stdout)[0].get('Containers',{}))<=set(self.ids.values()),'cleanup_foreign_endpoint')
   down=self.compose('down','--timeout','10',timeout=60);self.save('cleanup/compose-down.txt',down.stdout+down.stderr)
   current=self.inventory();names=self.text('network','ls','--format','{{.Name}}').splitlines()
   result['new_namespaces_removed']=not any(name.startswith(PROJECT+'-') for name in current) and NETWORK not in names
   result['unrelated_containers_preserved']=same_inventory(self.original_inventory,{k:current[k] for k in self.original_inventory if k in current})
   result['restored']=all(result[k] for k in ('temporary_tables_removed','new_namespaces_removed','unrelated_containers_preserved')) and result.get('post_rule_removal_control',{}).get('status','HTTP_OK')=='HTTP_OK'
  except Exception as error:result['error_code']=str(error) if isinstance(error,EvidenceError) else 'cleanup_failed'
  self.save('cleanup/result.json',result);return result
 def finish(self,cleanup):
  bundle={'schema_version':1,'origin':'docker_live','execution_id':self.execution_id,'suricata_version':self.version,'method':'NFQUEUE','phases':self.phases,'cleanup':cleanup,'ended_at':now()}
  self.save('bundle.json',bundle)
  artifacts=[]
  for p in sorted(self.path.rglob('*')):
   if p.is_file():artifacts.append({'file':p.relative_to(self.path).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size_bytes':p.stat().st_size})
  self.save('manifest.json',{'artifacts':artifacts,'independently_verified':False})
  report=build_report(self.path);self.save('report.json',report);write_pdf(report,self.path/'report.pdf')
  self.save('report-manifest.json',{'artifacts':[{'file':name,'sha256':hashlib.sha256((self.path/name).read_bytes()).hexdigest(),'size_bytes':(self.path/name).stat().st_size} for name in ['manifest.json','report.json','report.pdf']],'independently_verified':False})
  return report

def execute(root):
 runner=Runner(root);error=None;error_type=None;stage='preflight'
 try:
  runner.preflight();stage='deploy';runner.deploy();stage='before';runner.phase('before');stage='after';runner.phase('after')
 except Exception as caught:
  error=str(caught) if isinstance(caught,EvidenceError) else 'IPS_execution_failed';error_type=type(caught).__name__
  import traceback
  runner.save('failure-trace.txt',''.join(traceback.format_tb(caught.__traceback__)))
 finally:cleanup=runner.cleanup()
 if error:
  runner.save('failure.json',{'status':'ERROR','error_code':error,'stage':stage,'error_type':error_type,'cleanup':cleanup,'phases_completed':list(runner.phases),'blocking_verification':'NOT_CONFIRMED'})
  report=failure_report(runner.execution_id,error,stage,cleanup)
  runner.save('report.json',report);write_pdf(report,runner.path/'report.pdf')
  runner.save('failure-manifest.json',{'independently_verified':False,'artifacts':[{'file':p.relative_to(runner.path).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size_bytes':p.stat().st_size} for p in sorted(runner.path.rglob('*')) if p.is_file()]})
  return {'status':'ERROR','error_code':error,'stage':stage,'error_type':error_type,'run_directory':str(runner.path),'cleanup':cleanup,'blocking_verification':'NOT_CONFIRMED'}
 report=runner.finish(cleanup)
 return {'status':'PASS' if all(x['status']=='PASS' for x in report['results']) else 'NEEDS_REVIEW','run_directory':str(runner.path),'phases':report['phases'],'cleanup':cleanup,'policy_comparison':report['policy_comparison']['result']}
