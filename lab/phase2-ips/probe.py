"""Harmless HTTP endpoint/probe and scoped bounded TCP capture for IPS LAB."""
import base64,json,os,re,select,socket,struct,sys,time
from datetime import datetime,timezone
from pathlib import Path
A='10.207.10.10';B='10.207.20.10';PORT=8080

def now():return datetime.now(timezone.utc).isoformat()
def decode(frame,ptype):
 if len(frame)<54 or frame[12:14]!=b'\x08\x00':return None
 ip=frame[14:];ihl=(ip[0]&15)*4
 if ip[0]>>4!=4 or ihl<20 or len(ip)<ihl+20 or ip[9]!=6 or struct.unpack('!H',ip[6:8])[0]&8191:return None
 src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20]);tcp=ip[ihl:]
 sport,dport,seq,ack=struct.unpack('!HHII',tcp[:12]);thl=(tcp[12]>>4)*4
 if (src,dst) not in ((A,B),(B,A)) or PORT not in (sport,dport) or thl<20 or len(tcp)<thl:return None
 payload=tcp[thl:];match=re.search(rb'GET (/[^ \r\n]{1,160}) HTTP/1\.[01]',payload)
 return {'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'seq':seq,'ack':ack,'flags':tcp[13],
         'ttl':ip[8],'direction':'out' if ptype==4 else 'in','payload_size':len(payload),'uri':match[1].decode('ascii','replace') if match else None}

def capture():
 sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));sock.bind(('data0',0));records=[]
 pcap=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,1536,1))
 print(json.dumps({'ready':True}),flush=True)
 if sys.stdin.readline().strip()!='GO':return
 start=now();deadline=time.monotonic()+9
 try:
  while time.monotonic()<deadline:
   if not select.select([sock],[],[],min(.1,max(0,deadline-time.monotonic())))[0]:continue
   frame,addr=sock.recvfrom(1536);r=decode(frame,addr[2])
   if r is None:continue
   if len(records)>=512:raise RuntimeError('capture_limit_exceeded')
   ts=time.time();sec=int(ts);pcap.extend(struct.pack('<IIII',sec,int((ts-sec)*1000000),len(frame),len(frame))+frame)
   r['timestamp']=now();records.append(r)
 finally:
  stats=sock.getsockopt(263,6,12);kernel_packets,kernel_drops=struct.unpack('II',stats[:8]);sock.close()
 print(json.dumps({'kernel_packets':kernel_packets,'kernel_drops':kernel_drops,'records':records,'pcap_base64':base64.b64encode(pcap).decode(),'started_at':start,'ended_at':now(),'complete':True}),flush=True)

def request(uri):
 if not re.fullmatch(r'/(?:control|ips-lab-marker)\?run=[a-z0-9-]{1,96}',uri):raise ValueError('unsafe_request_path')
 result={'uri':uri,'source':A,'destination':B,'destination_port':PORT,'started_at':now()}
 s=socket.socket();s.settimeout(3);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
 try:
  s.bind((A,0));s.connect((B,PORT));result['source_port']=s.getsockname()[1]
  s.sendall(f'GET {uri} HTTP/1.1\r\nHost: ips-lab.local\r\nConnection: close\r\n\r\n'.encode())
  data=b''
  while len(data)<8192:
   part=s.recv(4096)
   if not part:break
   data+=part
  result.update(status='HTTP_OK' if data.startswith(b'HTTP/1.0 200') or data.startswith(b'HTTP/1.1 200') else 'HTTP_ERROR',status_code=200 if b' 200 ' in data.split(b'\r\n',1)[0] else None,response_contains_request=uri.encode() in data)
 except socket.timeout:result['status']='TIMEOUT'
 except (ConnectionResetError,BrokenPipeError):result['status']='RESET'
 except OSError:result['status']='SOCKET_ERROR'
 finally:s.close()
 result['ended_at']=now();print(json.dumps(result))

def serve():
 from http.server import HTTPServer,BaseHTTPRequestHandler
 class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
   if self.client_address[0]!=A or not self.path.startswith(('/control?run=','/ips-lab-marker?run=')):
    self.send_error(403);return
   row={'timestamp':now(),'source':self.client_address[0],'source_port':self.client_address[1],'uri':self.path,'method':'GET'}
   with Path('/tmp/server-events.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(row)+'\n')
   body=('IPS-LAB-OK '+self.path).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*args):pass
 HTTPServer((B,PORT),Handler).serve_forever()

def status():
 import subprocess
 def call(*a):return json.loads(subprocess.run(a,check=True,capture_output=True,text=True).stdout)
 role=os.environ['IPS_LAB_ROLE'];target=B if role=='client' else A
 result={'role':role,'ready':Path('/tmp/ready').is_file(),'default_routes':call('ip','-j','route','show','default'),
  'route':call('ip','-j','route','get',target),'addresses':call('ip','-j','addr','show','dev','data0'),
  'ip_forward':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
  'accept_redirects':Path('/proc/sys/net/ipv4/conf/data0/accept_redirects').read_text().strip(),
  'nft':call('nft','-j','list','ruleset')}
 if role=='server':result['server_events']=[json.loads(line) for line in Path('/tmp/server-events.jsonl').read_text().splitlines()] if Path('/tmp/server-events.jsonl').exists() else []
 print(json.dumps(result))

if __name__=='__main__':
 action=sys.argv[1]
 if action=='serve':serve()
 elif action=='capture':capture()
 elif action=='request':request(sys.argv[2])
 elif action=='status':status()
 else:raise SystemExit('unsupported action')
