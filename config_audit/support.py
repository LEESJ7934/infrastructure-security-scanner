"""Common support declarations, distinct from a successful measurement."""
from copy import deepcopy

SUPPORT = {
 'linux_mysql': {'platforms':['Ubuntu 24.04 fixed isolated LAB','MySQL 8.4.13 fixed isolated LAB'],
     'scope':'effective root/loopback SSH, selected files/processes/settings and lab_app privileges',
     'requires_review':['uncollected SSH Match contexts','PAM policy','host-wide accounts and services','patch/backport status'],
     'not_proved':['actual remote authentication','syslog delivery','TCP TLS identity']},
 'windows': {'platforms':['Windows Server 2022 build 20348 LAB; 2019/2025 candidates'],
     'scope':'local SAM, system audit subcategories, ActiveStore firewall and SMB server settings',
     'requires_review':['domain GPO/RSOP and FGPP','per-user audit','business service applicability'],
     'not_proved':['effective domain user policy','traffic enforcement','negotiated SMB signing']},
 'web_was': {'platforms':['nginx 1.30.6 LAB','Tomcat 10.1.61 LAB'],
     'scope':'supported explicit nginx literal contexts and supplied includes; strict single Tomcat host/connector',
     'requires_review':['regex/named/dynamic nginx locations','unresolved include','unknown directives','uncollected deployed contexts'],
     'not_proved':['all customer virtual hosts','TLS security','business application security']},
 'network': {'platforms':['isolated Linux FRR router and Docker bridge LAB'],
     'scope':'selected effective input chain/listeners/FRR settings and bridge membership',
     'requires_review':['other chains/namespaces','physical switch control plane','vendor-specific semantics'],
     'not_proved':['802.1Q enforcement','physical unused-port shutdown','whole-network packet enforcement']},
 'aws': {'platforms':['explicit scoped AWS API response envelope'],
     'scope':'selected resource settings; complete pagination required for positive verdict',
     'requires_review':['full effective IAM permission semantics','uncollected resources','business rule purpose'],
     'not_proved':['end-to-end network reachability','actual log delivery','periodic review program']},
}


def support_scope(domain):
    result=deepcopy(SUPPORT[domain])
    result.update(standard_basis='Internal LAB criteria; KISA only through explicit verified selected adapter',
                  declaration_kind='IMPLEMENTATION_SUPPORT_NOT_MEASUREMENT')
    return result
