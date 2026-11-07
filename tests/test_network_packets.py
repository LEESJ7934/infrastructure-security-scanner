"""Synthetic Ethernet headers/config and mocked Docker; no real packets."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch

from config_audit import network_packets as packets
from config_audit.collectors.network_devices import NetworkInputError
from scripts.run_network_packets import main

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('packet_header_decoder',ROOT/'lab/phase2-packet/capture.py')
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)


def frame(src='10.204.10.10',dst='10.204.20.10',ttl=64,kind=8,seq=1):
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28,1,0,ttl,1,0,socket.inet_aton(src),socket.inet_aton(dst))
    return b'\0'*12+b'\x08\x00'+ip+struct.pack('!BBHHH',kind,0,0,123,seq)+b'CANARY_PAYLOAD'


def events():
    source,dest='10.204.10.10','10.204.20.10'
    result={'source':[],'router':[],'destination':[]}
    for seq in (1,2,3):
        request=capture.decode(frame(seq=seq),'data0',4,source,dest)
        reply=capture.decode(frame(src=dest,dst=source,kind=0,seq=seq),'data0',4,source,dest)
        result['source'] += [request,{**reply,'direction':'in','ttl':63}]
        result['router'] += [{**request,'direction':'in'}, {**request,'ttl':63}, {**reply,'direction':'in'}, {**reply,'ttl':63}]
        result['destination'] += [{**request,'direction':'in','ttl':63},reply]
    return result


def forward_doc(profile='fabric'):
    cfg=packets.PROFILES[profile];a='10.204.10.0' if profile=='fabric' else '10.203.10.0';b='10.204.20.0' if profile=='fabric' else '10.203.20.0'
    base={'family':'inet','table':cfg['table'],'chain':'forward'}
    rules=[]
    for incoming,outgoing,src,dst in [(cfg['if_a'],cfg['if_b'],a,b),(cfg['if_b'],cfg['if_a'],b,a)]:
        expr=[]
        for key,value in [('iifname',incoming),('oifname',outgoing)]:expr.append({'match':{'op':'==','left':{'meta':{'key':key}},'right':value}})
        for key,value in [('saddr',src),('daddr',dst)]:expr.append({'match':{'op':'==','left':{'payload':{'protocol':'ip','field':key}},'right':{'prefix':{'addr':value,'len':24}}}})
        expr += [{'counter':{'packets':0,'bytes':0}},{'accept':None}]
        rules.append({'rule':{**base,'expr':expr}})
    return {'nftables':[{'chain':{'family':'inet','table':cfg['table'],'name':'forward','type':'filter','hook':'forward','prio':0,'policy':'drop'}},*rules]}


class PacketTests(unittest.TestCase):
    def test_default_not_tested_no_docker_call(self):
        output=io.StringIO()
        with patch.object(packets,'prefix',side_effect=AssertionError()),redirect_stdout(output):self.assertEqual(main([]),0)
        self.assertEqual(json.loads(output.getvalue())['status'],'NOT_TESTED')

    def test_header_only_never_payload(self):
        result=capture.decode(frame(),'data0',4,'10.204.10.10','10.204.20.10')
        self.assertEqual(result['ttl'],64);self.assertEqual(result['icmp_type'],8)
        self.assertNotIn('CANARY',json.dumps(result));self.assertNotIn('payload',result)

    def test_other_ips_protocols_and_truncated_frames_ignored(self):
        self.assertIsNone(capture.decode(frame(src='10.204.30.10'),'data0',4,'10.204.10.10','10.204.20.10'))
        self.assertIsNone(capture.decode(b'bad','data0',4,'10.204.10.10','10.204.20.10'))
        self.assertIsNone(capture.decode(frame(kind=5),'data0',4,'10.204.10.10','10.204.20.10'))

    def test_full_bidirectional_router_ttl_hops(self):
        result=packets.path_points(events(),'10.204.10.10','10.204.20.10')
        self.assertTrue(result['router_path_verified']);self.assertIsNone(result['first_missing_stage'])
        self.assertEqual(set(result['counts'].values()),{3})

    def test_source_egress_no_router_ingress_locates_bridge_stage(self):
        data=events();data['router']=[];data['destination']=[]
        result=packets.path_points(data,'10.204.10.10','10.204.20.10')
        self.assertEqual(result['first_missing_stage'],'router_request_in');self.assertFalse(result['router_path_verified'])

    def test_one_routed_echo_cannot_hide_l2_bypass(self):
        data=events();data['router']=[event for event in data['router'] if event['sequence']==1]
        self.assertFalse(packets.path_points(data,'10.204.10.10','10.204.20.10')['router_path_verified'])

    def test_id_mismatch_or_no_ttl_decrement_not_proof(self):
        for field,value in [('id',999),('ttl',64)]:
            data=events()
            for event in data['router']:
                if event['direction']=='out':event[field]=value
            self.assertFalse(packets.path_points(data,'10.204.10.10','10.204.20.10')['router_path_verified'])

    def test_ping_success_and_loss_formats(self):
        self.assertEqual(packets.ping_stats('3 packets transmitted, 3 packets received, 0% packet loss',0)['status'],'PASS')
        self.assertEqual(packets.ping_stats('3 packets transmitted, 0 received, 100% packet loss',1)['status'],'FAIL')

    def test_ping_parse_errors_not_zero_filled(self):
        result=packets.ping_stats('CANARY error',2)
        self.assertEqual(result['status'],'ERROR');self.assertIsNone(result['received'])
        self.assertEqual(packets.ping_stats('3 packets transmitted, 4 received',0)['status'],'ERROR')

    def test_forward_rules_both_profiles_with_counter(self):
        for profile in ('existing','fabric'):
            result=packets.forward_rules(forward_doc(profile),packets.PROFILES[profile])
            self.assertEqual(result['status'],'PASS');self.assertTrue(result['a_to_b_rule'] and result['b_to_a_rule'])

    def test_extra_accept_or_missing_rule_not_pass(self):
        doc=forward_doc();doc['nftables'].pop()
        self.assertEqual(packets.forward_rules(doc,packets.PROFILES['fabric'])['status'],'NEEDS_REVIEW')
        doc=forward_doc();doc['nftables'].append({'rule':{'family':'inet','table':'phase2_packet_guard','chain':'forward','expr':[{'accept':None}]}})
        self.assertEqual(packets.forward_rules(doc,packets.PROFILES['fabric'])['status'],'NEEDS_REVIEW')

    def test_wrong_forward_policy_not_pass(self):
        doc=forward_doc();doc['nftables'][0]['chain']['policy']='accept'
        self.assertEqual(packets.forward_rules(doc,packets.PROFILES['fabric'])['status'],'NEEDS_REVIEW')

    def test_shared_fabric_isolated_no_privileged_host_or_ports(self):
        doc=json.loads((ROOT/'lab/phase2-packet/compose.json').read_text())
        self.assertEqual(doc['name'],'scanner-p2pkt');self.assertTrue(doc['networks']['fabric']['internal'])
        self.assertEqual(doc['networks']['fabric']['ipam']['config'][0]['subnet'],'10.204.0.0/16')
        for name,service in doc['services'].items():
            self.assertEqual(service['cap_add'],['NET_ADMIN','NET_RAW'])
            self.assertNotIn('privileged',service);self.assertNotIn('ports',service);self.assertNotIn('volumes',service)
            self.assertNotEqual(service.get('network_mode'),'host')
            options=service['networks']['fabric']['driver_opts']['com.docker.network.endpoint.sysctls']
            self.assertIn('accept_redirects=0',options)
            if name!='router':self.assertNotIn('net.ipv4.ip_forward',service['sysctls'])

    def test_remote_docker_context_rejected(self):
        outputs=['desktop-linux',json.dumps([{'Endpoints':{'docker':{'Host':'tcp://user:CANARY@remote:2375'}}}])]
        with patch.object(packets.net,'_run',side_effect=outputs):
            with self.assertRaises(NetworkInputError) as error:packets.prefix()
        self.assertNotIn('CANARY',str(error.exception))

    def test_foreign_container_rejected_before_probes(self):
        data=[{'Config':{'Labels':{'com.docker.compose.project':'other'}},'HostConfig':{},'State':{'Running':True}}]
        with patch.object(packets.net,'_run',return_value=json.dumps(data)):
            with self.assertRaises(NetworkInputError):packets.scope(['docker'],'existing')

    def test_stopped_container_has_specific_error(self):
        data=[{'Config':{'Labels':{'com.docker.compose.project':'scanner-p2pkt','com.docker.compose.service':'router'}},'HostConfig':{},'State':{'Running':False}}]
        with patch.object(packets.net,'_run',return_value=json.dumps(data)):
            with self.assertRaisesRegex(NetworkInputError,'packet_container_not_running'):packets.scope(['docker'],'fabric')

    def test_existing_config_pass_reference_kept_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';path.write_text(json.dumps({'results':[{'check_id':'NET-LAB-R03','status':'PASS'},{'check_id':'NET-LAB-R04','status':'PASS'}]}))
            raw=path.read_bytes();result=packets.configuration_reference(path)
            self.assertEqual(result['recorded_configuration_statuses'],{'NET-LAB-R03':'PASS','NET-LAB-R04':'PASS'})
            self.assertEqual(path.read_bytes(),raw)
            self.assertIn('not_packet_lab',result['scope'])

    def test_no_existing_output_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'evidence.json';path.write_text('PRESERVE')
            with patch('scripts.run_network_packets.collect',side_effect=AssertionError()),redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--execute','--output',str(path)]),2)
            self.assertEqual(path.read_text(),'PRESERVE')

    def test_probe_error_not_success_or_sensitive_exception(self):
        output=io.StringIO()
        with patch('scripts.run_network_packets.collect',side_effect=OSError('CANARY')),redirect_stdout(output):
            self.assertEqual(main(['--execute']),2)
        self.assertEqual(json.loads(output.getvalue())['status'],'ERROR');self.assertNotIn('CANARY',output.getvalue())


if __name__=='__main__':unittest.main()
