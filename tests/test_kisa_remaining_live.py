"""Synthetic parser/graph boundaries. These tests are never LAB attestations."""
from copy import deepcopy
import unittest
from config_audit.collectors.kisa_mysql_live import role_privileges, restricted_ruleset
from config_audit.collectors.kisa_web_live import app_listing, minimized, normalize, APPROVED
from config_audit.kisa_2026 import assess


class RemainingLiveNormalizationTests(unittest.TestCase):
    def test_transitive_role_admin_privilege_is_not_lost(self):
        accounts=[dict(user=n,host='localhost') for n in ('app','reader','admin')]
        roles=[dict(from_user='admin',from_host='localhost',to_user='reader',to_host='localhost'),
               dict(from_user='reader',from_host='localhost',to_user='app',to_host='localhost')]
        static=[dict(grantee="'admin'@'localhost'",privilege='SUPER')]
        effective,complete=role_privileges(accounts,static,[],roles,[],'')
        self.assertTrue(complete)
        self.assertEqual(effective['app@localhost'],['SUPER'])

    def test_proxy_and_cycle_expansion_are_bounded_and_conservative(self):
        accounts=[dict(user=n,host='localhost') for n in ('app','admin')]
        proxies=[dict(user='app',host='localhost',proxied_user='admin',proxied_host='localhost'),
                 dict(user='admin',host='localhost',proxied_user='app',proxied_host='localhost')]
        effective,complete=role_privileges(accounts,[],[dict(user='admin',host='localhost',privilege='SYSTEM_USER')],[],proxies,'')
        self.assertEqual(effective['app@localhost'],['SYSTEM_USER'])
        self.assertFalse(role_privileges(accounts,[],[],[],[],'unreviewed_role')[1])

    def test_unknown_role_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            role_privileges([dict(user='app',host='localhost')],[],[],
                [dict(from_user='missing',from_host='localhost',to_user='app',to_host='localhost')],[],'')

    def test_builtin_wildcard_proxy_is_retained_as_admin_capability(self):
        accounts=[dict(user='root',host='localhost'),dict(user='app',host='localhost')]
        proxy=[dict(user='root',host='localhost',proxied_user='',proxied_host='')]
        effective,_=role_privileges(accounts,[],[],[],proxy,'')
        self.assertEqual(effective['root@localhost'],['PROXY_ANY_ACCOUNT'])
        self.assertEqual(effective['app@localhost'],[])

    def test_http_failure_or_version_leak_cannot_pass(self):
        self.assertIsNone(minimized(dict(status=503,server='',body=''),200))
        self.assertFalse(minimized(dict(status=200,server='nginx/1.30.6',body=''),200))
        self.assertFalse(minimized(dict(status=404,server='lab',body='Apache Tomcat/10.1.61'),404))
        self.assertTrue(minimized(dict(status=200,server='nginx',body='LAB_TOMCAT_OK'),200))

    def test_tomcat_explicit_listing_and_ambiguous_xml(self):
        base='<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"><servlet><servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class><init-param><param-name>listings</param-name><param-value>{}</param-value></init-param></servlet></web-app>'
        self.assertTrue(app_listing(base.format('false')))
        self.assertFalse(app_listing(base.format('true')))
        self.assertIsNone(app_listing(base.format('unknown')))
        self.assertIsNone(app_listing('<!DOCTYPE x>'+base.format('false')))

    def test_nginx_and_tomcat_need_real_endpoint_shapes_and_full_inventory(self):
        xml='<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"><servlet><servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class><init-param><param-name>listings</param-name><param-value>false</param-value></init-param></servlet></web-app>'
        bundle=dict(collected_at='2026-01-01T00:00:00Z',nodes={
            'nginx':dict(version='1.30.6',values=dict(autoindex_disabled=True,tokens_hidden=True)),
            'tomcat':dict(version='10.1.61',values=dict(server_info_hidden=True))})
        http={}
        for asset in ('nginx','tomcat'):
            for path in ('normal','error','directory','backup','docs','examples'):
                http[asset+'_'+path]=dict(status=200 if path=='normal' else 404,body='LAB_TOMCAT_OK' if path=='normal' else '',server='lab')
        inventories={k:sorted(v) for k,v in APPROVED.items()}
        packet=normalize(bundle,inventories,xml,http)
        for row in packet['observations']: row['source_kind']='SYNTHETIC'
        report=assess(packet)
        self.assertEqual(report['summary']['PASS'],3)
        self.assertEqual(report['verified_lab_pass'],0)
        changed=deepcopy(inventories);changed['tomcat'].append('/usr/local/tomcat/webapps/unreviewed.bak')
        self.assertFalse(next(r for r in normalize(bundle,changed,xml,http)['observations'] if r['kisa_id']=='WEB-07' and r['asset_id']=='tomcat')['value']['unnecessary_files_absent'])

    def test_empty_ruleset_is_not_designated_ip_enforcement(self):
        self.assertFalse(restricted_ruleset({'nftables':[]}))
        self.assertFalse(restricted_ruleset({'nftables':[{'table':{'family':'inet','name':'other'}}]}))


if __name__=='__main__': unittest.main()
