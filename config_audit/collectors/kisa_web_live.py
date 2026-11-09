"""Real scoped Nginx/Tomcat queries, reusing the existing strict LAB collector.

Only fixed project containers, deployed file roots and unauthenticated LAB
endpoints are read. No configuration or lifecycle mutations in this collector.
"""
from datetime import datetime, timezone
import json
import re
import xml.etree.ElementTree as ET

from . import web_was
from ..kisa_2026 import PROFILE, assess

ROOTS = {'nginx': ['/srv', '/usr/share/nginx/html'],
         'tomcat': ['/usr/local/tomcat/webapps', '/usr/local/tomcat/webapps.dist']}
APPROVED = {'nginx': {'/srv/files/example.txt'}, 'tomcat': {
    '/usr/local/tomcat/webapps/lab/health.jsp',
    '/usr/local/tomcat/webapps/lab/files/example.txt',
    '/usr/local/tomcat/webapps/lab/WEB-INF/web.xml'}}


def app_listing(xml):
    if '<!' in xml or len(xml) > 65536:
        return None
    root = ET.fromstring(xml)
    ns = {'j': 'https://jakarta.ee/xml/ns/jakartaee'}
    servlet = root.findall('j:servlet', ns)
    params = root.findall('.//j:init-param', ns)
    if len(servlet) != 1 or len(params) != 1:
        return None
    if servlet[0].findtext('j:servlet-class', namespaces=ns) != 'org.apache.catalina.servlets.DefaultServlet':
        return None
    values = {p.findtext('j:param-name', namespaces=ns): p.findtext('j:param-value', namespaces=ns) for p in params}
    return values.get('listings') == 'false' if values.get('listings') in ('true', 'false') else None


def minimized(response, status):
    if not isinstance(response, dict) or response.get('status') != status:
        return None
    text = ' '.join(str(response.get(k, '')) for k in ('server', 'body', 'x_powered_by'))
    return not (response.get('x_powered_by') or re.search(
        r'nginx/|apache[ /-]*tomcat|apache-coyote|\b(?:ubuntu|debian|windows|linux)\b', text, re.I))


def normalize(bundle, inventories, app_xml, http):
    """Pure normalization also used by synthetic unit tests, never attestation."""
    observations = []
    for asset in ('nginx', 'tomcat'):
        node = bundle['nodes'][asset]
        files = inventories[asset]
        if not isinstance(files, list) or any(not isinstance(x, str) for x in files):
            raise ValueError('web_inventory_invalid')
        valid_inventory = all(any(x.startswith(root + '/') for root in ROOTS[asset]) for x in files)
        allowed = valid_inventory and set(files) == APPROVED[asset]
        known = node['values'].get('autoindex_disabled') if asset == 'nginx' else app_listing(app_xml)
        directory = http.get(asset+'_directory', {})
        listing_absent = directory.get('status') in (403, 404) and 'index of' not in directory.get('body', '').lower()
        normal = http.get(asset+'_normal', {})
        live = normal.get('status') == 200 and normal.get('body', '').strip() == 'LAB_TOMCAT_OK'
        settings_minimized = node['values'].get('tokens_hidden' if asset == 'nginx' else 'server_info_hidden')
        values = {
            'WEB-04': {'effective_config_listing_disabled': known,
                       'http_listing_absent': listing_absent if live else None,
                       'locations_inventory_complete': valid_inventory and known is not None},
            'WEB-07': {'filesystem_inventory_complete': valid_inventory,
                       'unnecessary_files_absent': allowed,
                       'http_unnecessary_paths_absent': all(http.get(asset+'_'+k, {}).get('status') == 404 for k in ('backup','docs','examples')) if live else None},
            'WEB-16': {'effective_config_minimized': settings_minimized,
                       'normal_response_minimized': minimized(normal, 200),
                       'error_response_minimized': minimized(http.get(asset+'_error'), 404)},
        }
        for id, value in values.items():
            observations.append(dict(kisa_id=id, asset_id=asset, value=value,
                collection_status='ERROR' if node.get('error_code') else 'COLLECTED',
                source_kind='SAVED_LAB', product_version=node.get('version'),
                collected_at=bundle['collected_at'], evidence_reference='web-live-raw.json'))
    return {'profile': PROFILE, 'observations': observations}


def collect():
    bundle = web_was.collect_docker()
    args, nodes = web_was.docker_scope()
    def execute(asset, command):
        return web_was.run(args + ['exec', nodes[asset]['Id']] + command)
    inventories = {}
    for asset, roots in ROOTS.items():
        lines = []
        for root in roots:
            # Roots are fixed constants; no input-controlled shell interpolation.
            command = f'if [ -d {root} ]; then find {root} \\( -type f -o -type l \\) -print; fi'
            lines.extend(execute(asset, ['sh', '-c', command]).splitlines())
        inventories[asset] = sorted(lines)
    app_xml = execute('tomcat', ['cat', '/usr/local/tomcat/webapps/lab/WEB-INF/web.xml'])
    http = json.loads(execute('tomcat', ['java','-cp','/opt/lab','SelectedProbe']))
    # This timestamp follows the supplemental filesystem and HTTP reads.
    measured_at = datetime.now(timezone.utc).isoformat()
    bundle['supplemental_collected_at'] = measured_at
    packet_bundle = dict(bundle, collected_at=measured_at)
    packet = normalize(packet_bundle, inventories, app_xml, http)
    raw = {'origin':'local_container_readonly', 'project':web_was.PROJECT,
           'collected_at':measured_at, 'existing_bundle':bundle, 'file_roots':ROOTS,
           'file_inventory':inventories, 'tomcat_app_web_xml':app_xml, 'http_responses':http,
           'scope':'All fixed deployed roots and contexts of the isolated two-container LAB; no production site claim.'}
    return raw, packet, assess(packet)
