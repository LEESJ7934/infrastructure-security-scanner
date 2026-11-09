"""Bounded read-only AWS acquisition. Import-safe; real SDK only in live_factory.

Injected clients exercise the identical collector without credentials/network.
Only projected allowlisted fields are persisted; no raw SDK response or errors.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import ipaddress
import re
import time
from urllib.parse import unquote, urlsplit

from .aws_scope import AwsOfflineError, AwsScope, reject_secrets, require
from config_audit.collectors.aws_security import CHECKS, RULE_VERSION, validate_document

OPERATIONS = {
 'sts': {'get_caller_identity': 'GetCallerIdentity'},
 'iam': {'get_account_summary':'GetAccountSummary','get_role':'GetRole','list_attached_role_policies':'ListAttachedRolePolicies',
         'list_role_policies':'ListRolePolicies','get_role_policy':'GetRolePolicy','get_policy':'GetPolicy','get_policy_version':'GetPolicyVersion'},
 'ec2': {'describe_security_groups':'DescribeSecurityGroups','describe_vpcs':'DescribeVpcs','describe_subnets':'DescribeSubnets',
         'describe_route_tables':'DescribeRouteTables','describe_internet_gateways':'DescribeInternetGateways',
         'describe_network_interfaces':'DescribeNetworkInterfaces','describe_network_acls':'DescribeNetworkAcls','describe_flow_logs':'DescribeFlowLogs'},
 'cloudtrail': {'describe_trails':'DescribeTrails','get_trail_status':'GetTrailStatus','get_event_selectors':'GetEventSelectors'},
}
RETRYABLE = {'Throttling','RequestLimitExceeded','ServiceUnavailable','Timeout'}
SAFE_ERRORS = {'AccessDenied','AccessDeniedException','UnauthorizedOperation','ExpiredToken','LoginRefreshRequired','Throttling','RequestLimitExceeded',
               'ServiceUnavailable','Timeout','NoCredentials','NoSuchEntity','ParseError','ScopeViolation','CallLimitExceeded','DeadlineExceeded','QueryFailed'}
INTERNAL_ERRORS = {'API_not_allowed','STS_identity_required','EndpointRejected','STS_identity_malformed','STS_account_mismatch','MockScriptExhausted','MockRequestMismatch'}


class AcquisitionError(AwsOfflineError):
    pass


def fail(code): raise AcquisitionError(code)


def checked(condition, code='ParseError'):
    if not condition: fail(code)


def now(): return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Limits:
    max_calls: int = 100
    max_pages: int = 10
    retries: int = 1
    connect_timeout: int = 3
    read_timeout: int = 8
    max_seconds: int = 120

    def validate(self):
        for key, low, high in [('max_calls',1,256),('max_pages',1,32),('retries',0,2),('connect_timeout',1,10),('read_timeout',1,30),('max_seconds',5,600)]:
            value=getattr(self,key); require(type(value) is int and low<=value<=high,'collection_limits_invalid')


def validate_targets(scope, plan, expected_account, allowed_regions):
    require(expected_account == scope.account_id, 'expected_account_scope_mismatch')
    require(isinstance(allowed_regions,(list,tuple)) and len(allowed_regions)==len(set(allowed_regions))
            and set(allowed_regions)==set(scope.regions),'explicit_regions_scope_mismatch')
    require(isinstance(plan,dict) and set(plan)=={'schema_version','vpcs','targets'} and type(plan['schema_version']) is int and plan['schema_version']==scope.schema_version,'target_plan_invalid')
    require(isinstance(plan['vpcs'],dict) and set(plan['vpcs'])<=set(scope.regions),'target_vpc_region_invalid')
    for resource in plan['vpcs'].values():
        scope.check_resource('ec2',resource);require(resource.startswith('vpc-'),'target_vpc_invalid')
    require(isinstance(plan['targets'],dict) and set(plan['targets'])==set(CHECKS),'eight_explicit_targets_required')
    for check,target in plan['targets'].items():
        require(isinstance(target,dict) and set(target)=={'region','resource_id'},'target_invalid')
        scope.check_section(check,{'service':CHECKS[check][0],**target},CHECKS[check][0])
        if CHECKS[check][0]=='ec2':
            require(target['region'] in plan['vpcs'],'target_vpc_mapping_required')
            if check == 'VPC-01' and target['resource_id'].startswith('vpc-'): require(target['resource_id']==plan['vpcs'][target['region']], 'target_vpc_invalid')
        if check=='FL-01':require(target['resource_id']==plan['vpcs'][target['region']],'flow_target_vpc_mismatch')
        if check=='CT-01' and not (scope.schema_version == 2 and target['resource_id'] == scope.account_id):require(target['region']==target['resource_id'].split(':')[3],'trail_home_region_target_required')
    reject_secrets(plan)


def live_factory(scope, limits):
    """Called only after explicit live CLI validation. No static key arguments."""
    limits.validate()
    try:
        import boto3
        from botocore.config import Config
    except ImportError: raise AwsOfflineError('aws_sdk_not_installed') from None
    config=Config(connect_timeout=limits.connect_timeout,read_timeout=limits.read_timeout,
        retries={'total_max_attempts':1},ignore_configured_endpoint_urls=True,
        use_dualstack_endpoint=False,use_fips_endpoint=False)
    session=boto3.session.Session(region_name=scope.regions[0])
    # Bound IMDS lookup where botocore's standard provider supports these knobs.
    session._session.set_config_variable('metadata_service_timeout',limits.connect_timeout)
    session._session.set_config_variable('metadata_service_num_attempts',1)
    def create(service,region):
        checked(service in OPERATIONS,'API_not_allowed')
        client=session.client(service,region_name=scope.regions[0] if region=='global' else region,config=config,verify=True)
        endpoint=urlsplit(client.meta.endpoint_url)
        suffix='.amazonaws.com.cn' if scope.partition=='aws-cn' else '.amazonaws.com'
        checked(endpoint.scheme=='https' and endpoint.hostname is not None and endpoint.hostname.endswith(suffix)
                and endpoint.username is None and endpoint.password is None,'EndpointRejected')
        return client
    return create


def error_code(error):
    name=type(error).__name__
    if name == 'LoginRefreshRequired': return 'LoginRefreshRequired'
    if isinstance(error,AcquisitionError):return str(error) if str(error) in SAFE_ERRORS|INTERNAL_ERRORS else 'QueryFailed'
    if name in {'NoCredentialsError','PartialCredentialsError','CredentialRetrievalError','SSOTokenLoadError'}:return 'NoCredentials'
    if isinstance(error,TimeoutError) or name in {'ConnectTimeoutError','ReadTimeoutError','EndpointConnectionError'}:return 'Timeout'
    response=getattr(error,'response',None)
    details=response.get('Error') if isinstance(response,dict) else None
    code=details.get('Code') if isinstance(details,dict) else None
    if isinstance(code,str) and code in SAFE_ERRORS:return code
    if code in {'ThrottlingException','TooManyRequestsException'}:return 'Throttling'
    if code in {'NoSuchEntityException','InvalidInstanceID.NotFound','InvalidGroup.NotFound','InvalidSubnetID.NotFound'}:return 'NoSuchEntity'
    return 'QueryFailed'


class Reader:
    def __init__(self,scope,factory,limits,*,clock=time.monotonic,sleep=time.sleep):
        limits.validate();self.scope=scope;self.factory=factory;self.limits=limits;self.clock=clock;self.sleep=sleep
        self.started=clock();self.clients={};self.identified=False;self.calls=0
        self.audit={'schema_version':1,'rule_version':RULE_VERSION if scope.schema_version == 1 else 'AWS-LAB-COLLECTION-0.2','started_at':now(),'expected_account_id':scope.account_id,'actual_account_id':None,'account_match':False,
                    'partition':scope.partition,'allowed_regions':list(scope.regions),'requests':[],'warnings':[], 'limits':vars(limits).copy()}

    def _params(self,service,operation,params,refs):
        required={
            'get_caller_identity':set(),'get_account_summary':set(),
            'get_role':{'RoleName'},'list_attached_role_policies':{'RoleName'},'list_role_policies':{'RoleName'},
            'get_role_policy':{'RoleName','PolicyName'},'get_policy':{'PolicyArn'},'get_policy_version':{'PolicyArn','VersionId'},
            'describe_security_groups':{'GroupIds'},'describe_vpcs':{'VpcIds'},'describe_subnets':{'SubnetIds'},
            'describe_network_acls':{'NetworkAclIds'},'describe_route_tables':{'Filters'},'describe_internet_gateways':{'Filters'},
            'describe_network_interfaces':{'Filters'},'describe_flow_logs':{'Filters'},'describe_trails':{'trailNameList','includeShadowTrails'},
            'get_trail_status':{'Name'},'get_event_selectors':{'TrailName'}}[operation]
        if operation == 'describe_trails' and self.scope.schema_version == 2 and 'trailNameList' not in params:
            checked(refs == [('cloudtrail', self.scope.account_id)] and params == {'includeShadowTrails': True}, 'ScopeViolation')
            required = {'includeShadowTrails'}
        checked(required<=set(params) and set(params)<=required|{'Marker','NextToken'},'ScopeViolation')
        if 'Filters' in required:
            checked(isinstance(params['Filters'],list) and params['Filters'],'ScopeViolation')
            names={f.get('Name') for f in params['Filters'] if isinstance(f,dict)}
            expected={'describe_internet_gateways':{'attachment.vpc-id'},'describe_network_interfaces':{'subnet-id'},'describe_flow_logs':{'resource-id'}}
            if operation in expected:checked(names==expected[operation],'ScopeViolation')
            if operation=='describe_route_tables':checked(names in ({'association.subnet-id'},{'vpc-id','association.main'}),'ScopeViolation')
        for ref_service,resource in refs:self.scope.check_resource(ref_service,resource)
        fields={'GroupIds','VpcIds','SubnetIds','NetworkInterfaceIds','NetworkAclIds','RouteTableIds','InternetGatewayIds','FlowLogIds'}
        for key,value in params.items():
            if key in fields:
                checked(isinstance(value,list) and value,'ScopeViolation')
                for resource in value:self.scope.check_resource('ec2',resource)
            if key in {'PolicyArn'}:self.scope.check_resource('iam',value)
            if key in {'Name','TrailName'} and service=='cloudtrail':self.scope.check_resource(service,value)
            if key=='trailNameList':
                checked(isinstance(value,list) and value,'ScopeViolation')
                for resource in value:self.scope.check_resource('cloudtrail',resource)
            if key=='RoleName':
                checked(value in [r.rsplit('/',1)[-1] for r in self.scope.resources.get('iam',()) if ':role/' in r],'ScopeViolation')
            if key=='Filters':
                for f in value:
                    checked(f.get('Name') in {'vpc-id','subnet-id','attachment.vpc-id','association.subnet-id','association.main','resource-id'},'ScopeViolation')
                    checked(isinstance(f.get('Values'),list) and f['Values'],'ScopeViolation')
                    for resource in f.get('Values',[]):
                        if f['Name']=='association.main':checked(resource=='true','ScopeViolation')
                        else:self.scope.check_resource('ec2',resource)

    def call(self,service,region,operation,params=None,refs=()):
        checked(operation in OPERATIONS.get(service,{}),'API_not_allowed')
        checked(self.identified or (service=='sts' and operation=='get_caller_identity'),'STS_identity_required')
        checked((region=='global' and service=='iam') or (region in self.scope.regions and service!='iam'),'ScopeViolation')
        if service!='sts':checked(service in self.scope.services,'ScopeViolation')
        params=params or {}
        try:self._params(service,operation,params,refs)
        except AwsOfflineError:fail('ScopeViolation')
        for attempt in range(self.limits.retries+1):
            if self.calls>=self.limits.max_calls:fail('CallLimitExceeded')
            if self.clock()-self.started>=self.limits.max_seconds:fail('DeadlineExceeded')
            self.calls+=1
            record={'api':service+':'+OPERATIONS[service][operation],'region':region,
                    'resource_ids':[r for _,r in refs],'attempt':attempt+1,'requested_at':now(),'success':False}
            try:
                if (service,region) not in self.clients:self.clients[service,region]=self.factory(service,region)
                response=getattr(self.clients[service,region],operation)(**params)
                checked(isinstance(response,dict),'ParseError')
                checked(self.clock()-self.started<=self.limits.max_seconds,'DeadlineExceeded')
                record['success']=True;record['completed_at']=now();self.audit['requests'].append(record)
                return response
            except Exception as error:
                code=error_code(error);record.update(error_code=code,completed_at=now());self.audit['requests'].append(record)
                if code in RETRYABLE and attempt<self.limits.retries:self.sleep(.1*(attempt+1));continue
                fail(code)

    def identity(self):
        response=self.call('sts',self.scope.regions[0],'get_caller_identity')
        account=response.get('Account');arn=response.get('Arn')
        checked(isinstance(account,str) and re.fullmatch(r'\d{12}',account) and isinstance(arn,str),'ParseError')
        pieces=arn.split(':',5)
        checked(len(pieces)==6 and pieces[1]==self.scope.partition and pieces[2] in {'iam','sts'} and pieces[4]==account,'STS_identity_malformed')
        if account!=self.scope.account_id:
            self.audit['actual_account_redacted']=True;fail('STS_account_mismatch')
        self.identified=True;self.audit.update(actual_account_id=account,account_match=True,identity_checked_at=now())

    def pages(self,service,region,operation,key,params,refs=(),iam=False):
        found=[];tokens=set();params=deepcopy(params);page=0
        def finish(complete,reason):
            self.audit.setdefault('pagination',[]).append({'api':service+':'+OPERATIONS[service][operation],
                'region':region,'pages':page,'complete':complete,'reason':reason})
            return found,page,complete
        try:
            while page<self.limits.max_pages:
                response=self.call(service,region,operation,params,refs);page+=1
                checked(isinstance(response.get(key),list),'ParseError');found.extend(response[key])
                checked(len(found)<=4096,'ParseError')
                if iam:
                    if type(response.get('IsTruncated')) is not bool:return finish(False,'pagination_metadata_missing')
                    more=response['IsTruncated'];token=response.get('Marker');field='Marker'
                else:
                    token=response.get('NextToken');more=token is not None and token!='';field='NextToken'
                if not more:return finish(True,'all_pages_read')
                if not isinstance(token,str) or not token or token in tokens:return finish(False,'token_missing_or_repeated')
                tokens.add(token);params[field]=token
            return finish(False,'page_limit_reached')
        except AcquisitionError as error:
            finish(False,str(error));raise


def pick(data,fields):
    checked(isinstance(data,dict),'ParseError')
    return {field:deepcopy(data[field]) for field in fields if field in data}


def single(rows,key,resource):
    checked(isinstance(rows,list) and len(rows)==1 and rows[0].get(key)==resource,'ParseError')
    return rows[0]


def owned(data,scope,vpc=None):
    checked(data.get('OwnerId')==scope.account_id,'ScopeViolation')
    if vpc is not None:checked(data.get('VpcId')==vpc,'ScopeViolation')


def policy_document(value):
    try:
        if isinstance(value,str):value=json.loads(unquote(value))
        checked(isinstance(value,dict),'ParseError')
        # Descriptions/tags/trust policy are not copied. Policy semantics needed
        # for the existing interpreter remain intact, after secret screening.
        document=pick(value,['Version','Statement']);reject_secrets(document)
        return document
    except (ValueError,TypeError,AwsOfflineError):fail('ParseError')


class Collector:
    def __init__(self,reader,plan,origin):
        self.reader=reader;self.scope=reader.scope;self.plan=plan;self.origin=origin;self.summary_cache=None;self.summary_error=None
        self.summary_request_indexes=[];self.summary_collected_at=None

    def ec2_pages(self,region,operation,key,params,refs):return self.reader.pages('ec2',region,operation,key,params,refs)

    def account_summary(self,target):
        if self.summary_error:fail(self.summary_error)
        if self.summary_cache is None:
            request_start=len(self.reader.audit['requests'])
            try:
                response=self.reader.call('iam','global','get_account_summary',refs=[('iam',self.scope.account_id)])
                checked(isinstance(response.get('SummaryMap'),dict),'ParseError')
                self.summary_cache={'SummaryMap':pick(response['SummaryMap'],['AccountAccessKeysPresent','AccountMFAEnabled','AccountPasswordPresent','AccountSigningCertificatesPresent'])}
            except AcquisitionError as error:self.summary_error=str(error);raise
            finally:
                self.summary_request_indexes=list(range(request_start,len(self.reader.audit['requests'])))
                self.summary_collected_at=now()
        # Centralized-root management cannot be verified by this API alone.
        return deepcopy(self.summary_cache),1,True

    def role(self,target):
        arn=target['resource_id'];name=arn.rsplit('/',1)[-1];refs=[('iam',arn)]
        role=self.reader.call('iam','global','get_role',{'RoleName':name},refs).get('Role')
        checked(isinstance(role,dict) and role.get('Arn')==arn,'ScopeViolation')
        attached,p1,c1=self.reader.pages('iam','global','list_attached_role_policies','AttachedPolicies',{'RoleName':name},refs,iam=True)
        inline,p2,c2=self.reader.pages('iam','global','list_role_policies','PolicyNames',{'RoleName':name},refs,iam=True)
        documents=[];complete=c1 and c2
        for ref in attached:
            checked(isinstance(ref,dict) and isinstance(ref.get('PolicyArn'),str),'ParseError')
            policy_arn=ref['PolicyArn']
            try:self.scope.check_resource('iam',policy_arn)
            except AwsOfflineError:
                complete=False;self.reader.audit['warnings'].append('attached_policy_outside_explicit_scope');continue
            policy=self.reader.call('iam','global','get_policy',{'PolicyArn':policy_arn},[('iam',policy_arn)]).get('Policy')
            checked(isinstance(policy,dict) and policy.get('Arn')==policy_arn and re.fullmatch(r'v\d+',str(policy.get('DefaultVersionId',''))),'ParseError')
            version=self.reader.call('iam','global','get_policy_version',{'PolicyArn':policy_arn,'VersionId':policy['DefaultVersionId']},[('iam',policy_arn)]).get('PolicyVersion')
            checked(isinstance(version,dict) and version.get('VersionId')==policy['DefaultVersionId'] and 'Document' in version
                    and version.get('IsDefaultVersion') is True,'ParseError')
            documents.append(policy_document(version['Document']))
        for policy_name in inline:
            checked(isinstance(policy_name,str) and re.fullmatch(r'[\w+=,.@-]{1,128}',policy_name),'ParseError')
            policy=self.reader.call('iam','global','get_role_policy',{'RoleName':name,'PolicyName':policy_name},refs)
            checked(policy.get('RoleName')==name and policy.get('PolicyName')==policy_name and 'PolicyDocument' in policy,'ParseError')
            documents.append(policy_document(policy['PolicyDocument']))
        if role.get('PermissionsBoundary'):self.reader.audit['warnings'].append('permissions_boundary_not_evaluated_as_effective_access')
        return {'RoleArn':arn,'PolicySetComplete':complete,'PolicyDocuments':documents},max(p1,p2),complete

    def sg(self,target):
        region=target['region'];rid=target['resource_id'];vpc=self.plan['vpcs'][region]
        data,pages,complete=self.ec2_pages(region,'describe_security_groups','SecurityGroups',{'GroupIds':[rid]},[('ec2',rid)])
        group=single(data,'GroupId',rid);owned(group,self.scope,vpc)
        result=pick(group,['GroupId','VpcId','IpPermissions'])
        # Project only supported permission fields; do not copy descriptions/tags.
        if isinstance(result.get('IpPermissions'),list):
            result['IpPermissions']=[pick(p,['IpProtocol','FromPort','ToPort','IpRanges','Ipv6Ranges','UserIdGroupPairs','PrefixListIds']) for p in result['IpPermissions']]
            for p in result['IpPermissions']:
                for field,keys in [('IpRanges',['CidrIp']),('Ipv6Ranges',['CidrIpv6']),('UserIdGroupPairs',['GroupId']),('PrefixListIds',['PrefixListId'])]:
                    if field in p:p[field]=[pick(row,keys) for row in p[field]]
        return result,pages,complete

    def topology(self, target):
        region = target['region']; vpc = target['resource_id']; results = []; complete = True; pages = 0
        vpcs, n, c = self.ec2_pages(region, 'describe_vpcs', 'Vpcs', {'VpcIds':[vpc]}, [('ec2',vpc)])
        owned(single(vpcs,'VpcId',vpc), self.scope); pages += n; complete &= c
        ids = [r for r in self.scope.resources['ec2'] if r.startswith('subnet-')]
        checked(ids, 'ParseError')
        for rid in ids:
            subnets,n,c = self.ec2_pages(region,'describe_subnets','Subnets',{'SubnetIds':[rid]},[('ec2',rid)])
            pages += n; complete &= c; subnet = single(subnets,'SubnetId',rid); owned(subnet,self.scope,vpc)
            tables,n,c = self.ec2_pages(region,'describe_route_tables','RouteTables',{'Filters':[{'Name':'association.subnet-id','Values':[rid]}]},[('ec2',rid)])
            pages += n; complete &= c
            if not tables:
                checked(c, 'ParseError')
                tables,n,c = self.ec2_pages(region,'describe_route_tables','RouteTables',{'Filters':[{'Name':'vpc-id','Values':[vpc]},{'Name':'association.main','Values':['true']}]},[('ec2',vpc)])
                pages += n; complete &= c
            checked(len(tables)==1,'ParseError'); table=tables[0]; owned(table,self.scope,vpc)
            self.scope.check_resource('ec2',table.get('RouteTableId'))
            associations=table.get('Associations'); checked(isinstance(associations,list),'ParseError')
            resolved=any(a.get('SubnetId')==rid or a.get('Main') is True for a in associations)
            checked(type(subnet.get('MapPublicIpOnLaunch')) is bool and isinstance(table.get('Routes'),list),'ParseError')
            routes=[]
            for route in table['Routes']:
                item=pick(route,['State','DestinationCidrBlock','DestinationIpv6CidrBlock'])
                checked('DestinationCidrBlock' in item or 'DestinationIpv6CidrBlock' in item, 'ParseError')
                for key,version in [('DestinationCidrBlock',4),('DestinationIpv6CidrBlock',6)]:
                    if key in item: checked(ipaddress.ip_network(item[key],strict=False).version==version, 'ParseError')
                gateway=route.get('GatewayId','')
                checked(isinstance(gateway,str), 'ParseError')
                item['GatewayKind']='internet' if gateway.startswith('igw-') else 'local' if gateway=='local' else 'nat' if route.get('NatGatewayId') else 'unknown'
                routes.append(item)
            enis,n,c=self.ec2_pages(region,'describe_network_interfaces','NetworkInterfaces',{'Filters':[{'Name':'subnet-id','Values':[rid]}]},[('ec2',rid)])
            pages += n; complete &= c; public_count=0; ipv6_count=0
            for eni in enis:
                owned(eni,self.scope,vpc); checked(eni.get('SubnetId')==rid,'ScopeViolation')
                if eni.get('NetworkInterfaceId') not in self.scope.resources['ec2']:
                    complete=False
                    self.reader.audit['warnings'].append('ENI_filtered_outside_explicit_resource_scope')
                    continue
                checked(isinstance(eni.get('Association',{}),dict),'ParseError')
                public_count += bool(eni.get('Association',{}).get('PublicIp'))
                checked(isinstance(eni.get('Ipv6Addresses'),list),'ParseError')
                for address in eni['Ipv6Addresses']: ipv6_count += ipaddress.ip_address(address['Ipv6Address']).is_global
            results.append({'SubnetId':rid,'VpcId':vpc,'MapPublicIpOnLaunch':subnet['MapPublicIpOnLaunch'],
                'RouteTableId':table['RouteTableId'],'AssociationResolved':resolved,'Routes':routes,'PublicIPv4ENICount':public_count,'PublicIPv6ENICount':ipv6_count})
        return {'VpcId':vpc,'TopologySubnets':results},pages,complete

    def subnet(self,target):
        if self.scope.schema_version == 2 and target['resource_id'].startswith('vpc-'): return self.topology(target)
        region=target['region'];rid=target['resource_id'];vpc=self.plan['vpcs'][region]
        vpcs,p0,c0=self.ec2_pages(region,'describe_vpcs','Vpcs',{'VpcIds':[vpc]},[('ec2',vpc)])
        owned(single(vpcs,'VpcId',vpc),self.scope)
        subnets,p1,c1=self.ec2_pages(region,'describe_subnets','Subnets',{'SubnetIds':[rid]},[('ec2',rid)])
        subnet=single(subnets,'SubnetId',rid);owned(subnet,self.scope,vpc)
        tables,p2,c2=self.ec2_pages(region,'describe_route_tables','RouteTables',{'Filters':[{'Name':'association.subnet-id','Values':[rid]}]},[('ec2',rid)])
        if not tables:
            checked(c2,'ParseError')
            tables,p2b,c2b=self.ec2_pages(region,'describe_route_tables','RouteTables',{'Filters':[{'Name':'vpc-id','Values':[vpc]},{'Name':'association.main','Values':['true']}]},[('ec2',vpc)])
            p2+=p2b;c2=c2 and c2b
        checked(len(tables)==1,'ParseError');table=tables[0];owned(table,self.scope,vpc)
        self.scope.check_resource('ec2',table.get('RouteTableId'))
        gateways,p3,c3=self.ec2_pages(region,'describe_internet_gateways','InternetGateways',{'Filters':[{'Name':'attachment.vpc-id','Values':[vpc]}]},[('ec2',vpc)])
        for gateway in gateways:
            owned(gateway,self.scope);self.scope.check_resource('ec2',gateway.get('InternetGatewayId'))
            checked(any(a.get('VpcId')==vpc for a in gateway.get('Attachments',[])),'ScopeViolation')
        enis,p4,c4=self.ec2_pages(region,'describe_network_interfaces','NetworkInterfaces',{'Filters':[{'Name':'subnet-id','Values':[rid]}]},[('ec2',rid)])
        projected=[]
        for eni in enis:
            owned(eni,self.scope,vpc);checked(eni.get('SubnetId')==rid,'ScopeViolation')
            if eni.get('NetworkInterfaceId') not in self.scope.resources['ec2']:
                c4=False;self.reader.audit['warnings'].append('ENI_filtered_outside_explicit_resource_scope');continue
            item=pick(eni,['NetworkInterfaceId','SubnetId','Ipv6Addresses'])
            # AWS omits Association for a private-only interface.
            item['Association']=pick(eni.get('Association',{}),['PublicIp'])
            if 'Ipv6Addresses' in item:item['Ipv6Addresses']=[pick(a,['Ipv6Address']) for a in item['Ipv6Addresses']]
            projected.append(item)
        associations=[pick(a,['SubnetId','Main']) for a in table.get('Associations',[]) if a.get('SubnetId')==rid or a.get('Main') is True]
        routes=[pick(route,['DestinationCidrBlock','DestinationIpv6CidrBlock','GatewayId','NatGatewayId','State']) for route in table.get('Routes',[])]
        # Unknown route target kinds must remain unknown, never become local.
        result=pick(subnet,['SubnetId','VpcId','MapPublicIpOnLaunch'])
        result.update(RouteTableAssociationResolved=bool(associations),RouteTable={'VpcId':vpc,'RouteTableId':table['RouteTableId'],'Associations':associations,'Routes':routes},NetworkInterfaces=projected)
        return result,p0+p1+p2+p3+p4,c0 and c1 and c2 and c3 and c4

    def nacl(self,target):
        region=target['region'];rid=target['resource_id'];vpc=self.plan['vpcs'][region]
        entries,pages,complete=self.ec2_pages(region,'describe_network_acls','NetworkAcls',{'NetworkAclIds':[rid]},[('ec2',rid)])
        acl=single(entries,'NetworkAclId',rid);owned(acl,self.scope,vpc)
        result=pick(acl,['NetworkAclId','VpcId'])
        if 'Associations' in acl:result['Associations']=[pick(a,['SubnetId']) for a in acl['Associations'] if a.get('SubnetId') in self.scope.resources['ec2']]
        if 'Entries' in acl:result['Entries']=[pick(e,['RuleNumber','Egress','Protocol','RuleAction','CidrBlock','Ipv6CidrBlock','PortRange']) for e in acl['Entries']]
        return result,pages,complete

    def trail_list(self, target):
        region=target['region']
        response=self.reader.call('cloudtrail',region,'describe_trails',{'includeShadowTrails':True},[('cloudtrail',self.scope.account_id)])
        checked(isinstance(response.get('trailList'),list) and len(response['trailList']) <= 4096,'ParseError')
        complete=not bool(response.get('NextToken')); results=[]; seen=set()
        for entry in response['trailList']:
            checked(isinstance(entry,dict) and isinstance(entry.get('TrailARN'),str),'ParseError')
            arn=entry['TrailARN']
            try: self.scope.check_resource('cloudtrail',arn)
            except AwsOfflineError:
                complete=False; self.reader.audit['warnings'].append('trail_outside_authorized_account_or_region'); continue
            checked(arn not in seen,'ParseError'); seen.add(arn)
            if entry.get('HomeRegion') not in self.scope.regions:
                complete=False; continue
            result,_,c=self.trail({'region':entry['HomeRegion'],'resource_id':arn})
            if not result.get('TrailPresent'): complete=False
            results.append(result); complete &= c
        return {'TrailInventory':results,'EventHistoryEvaluated':False},1,complete

    def trail(self,target):
        if self.scope.schema_version == 2 and target['resource_id']==self.scope.account_id: return self.trail_list(target)
        arn=target['resource_id'];home=arn.split(':')[3];refs=[('cloudtrail',arn)]
        response=self.reader.call('cloudtrail',home,'describe_trails',{'trailNameList':[arn],'includeShadowTrails':True},refs)
        checked(isinstance(response.get('trailList'),list) and len(response['trailList']) <= 4096,'ParseError')
        trails=response['trailList']
        complete = not bool(response.get('NextToken')) if self.scope.schema_version == 2 else True
        if not trails:return {'TrailPresent':False},1,complete
        trail=single(trails,'TrailARN',arn);checked(trail.get('HomeRegion')==home,'ScopeViolation')
        regional={}
        for region in self.scope.regions:
            status=self.reader.call('cloudtrail',region,'get_trail_status',{'Name':arn},refs)
            checked(type(status.get('IsLogging')) is bool,'ParseError')
            regional[region]={'IsLogging':status['IsLogging'],'LatestDeliveryError':'reported_error' if status.get('LatestDeliveryError') else ''}
        selectors=self.reader.call('cloudtrail',home,'get_event_selectors',{'TrailName':arn},refs)
        checked(selectors.get('TrailARN')==arn,'ScopeViolation')
        checked('EventSelectors' in selectors or 'AdvancedEventSelectors' in selectors,'ParseError')
        checked(all(isinstance(selectors.get(k,[]),list) for k in ('EventSelectors','AdvancedEventSelectors')),'ParseError')
        result=pick(trail,['TrailARN','HomeRegion','IsMultiRegionTrail','IncludeGlobalServiceEvents','IsOrganizationTrail'])
        result.update(TrailPresent=True,Status=regional[home],RegionalStatuses=regional,CollectionRequiredRegions=list(self.scope.regions))
        result.update({k:deepcopy(selectors.get(k,[])) for k in ('EventSelectors','AdvancedEventSelectors')})
        if trail.get('IsOrganizationTrail'):self.reader.audit['warnings'].append('organization_trail_visibility_limited_to_authorized_account_regions')
        return result,1,complete

    def flows(self,target):
        region=target['region'];vpc=target['resource_id']
        targets=[vpc]
        if self.scope.schema_version == 2:
            targets += [r for r in self.scope.resources['ec2'] if r.startswith(('subnet-','eni-'))]
        flows,pages,complete=self.ec2_pages(region,'describe_flow_logs','FlowLogs',{'Filters':[{'Name':'resource-id','Values':targets}]},[('ec2',r) for r in targets])
        result=[]
        for flow in flows:
            checked(flow.get('ResourceId') in targets,'ScopeViolation')
            if self.scope.schema_version == 1 and flow.get('FlowLogId') not in self.scope.resources['ec2']:
                complete=False;self.reader.audit['warnings'].append('flow_log_filtered_outside_explicit_resource_scope');continue
            item=pick(flow,['FlowLogId','ResourceId','TrafficType','FlowLogStatus','DeliverLogsStatus','LogDestinationType','LogDestination'])
            if item.get('LogDestinationType')=='cloud-watch-logs' and isinstance(item.get('LogDestination'),str) and item['LogDestination'].endswith(':*'):
                # CloudWatch's log-group ARN suffix is not an authorization to
                # enumerate arbitrary groups. Match the exact canonical group.
                item['LogDestination']=item['LogDestination'][:-2]
            if self.scope.schema_version == 2:
                checked(isinstance(item.get('LogDestination'),str) and bool(item['LogDestination']), 'ParseError')
                item['LogDestinationConfigured']=True
                item.pop('LogDestination',None)  # Unapproved destination identifiers are never exported.
            result.append(item)
        return {'TargetResourceId':vpc,'FlowLogs':result},pages,complete

    def collect(self):
        sections={}
        handlers={'IAM-01':self.account_summary,'IAM-02':self.account_summary,'IAM-03':self.role,'SG-01':self.sg,
                  'VPC-01':self.subnet,'NACL-01':self.nacl,'CT-01':self.trail,'FL-01':self.flows}
        for check in CHECKS:
            target=self.plan['targets'][check];base={'service':CHECKS[check][0],**target}
            start=len(self.reader.audit['requests'])
            page_start=len(self.reader.audit.get('pagination',[]))
            try:
                data,pages,complete=handlers[check](target);reject_secrets(data)
                section={**base,'state':'COLLECTED','collected_at':now(), 'pagination':{'complete':complete,'pages':max(1,pages),'next_token_present':not complete},'data':data}
                # Reuse the offline scope validator before retaining any data.
                from config_audit.collectors.aws_security import _graph_scope
                _graph_scope(self.scope,data)
                sections[check]=section
            except Exception as error:
                code=error_code(error)
                if isinstance(error,AwsOfflineError) and not isinstance(error,AcquisitionError):code='ScopeViolation' if 'scope' in str(error).lower() else 'ParseError'
                if code not in SAFE_ERRORS:code='QueryFailed'
                sections[check]={**base,'state':'ERROR','collected_at':now(),'data':None,'error_code':code,
                    'pagination':{'complete':False,'pages':sum(p['pages'] for p in self.reader.audit.get('pagination',[])[page_start:]),'next_token_present':True}}
            self.reader.audit.setdefault('checks',{})[check]={'state':sections[check]['state'],'complete':sections[check]['pagination']['complete'],
                'api_request_indexes':self.summary_request_indexes if check in ('IAM-01','IAM-02') else list(range(start,len(self.reader.audit['requests'])))}
            if check in ('IAM-01','IAM-02') and self.summary_collected_at:sections[check]['collected_at']=self.summary_collected_at
        document={'schema_version':1,'origin':self.origin,'account_id':self.scope.account_id,'partition':self.scope.partition,'collected_at':now(),'sections':sections}
        validate_document(document,self.scope)
        self.reader.audit.update(completed_at=now(),call_count=self.reader.calls,credential_provider_calls_included=False)
        return document,self.reader.audit


def collect(scope,plan,*,expected_account,allowed_regions,factory,limits=None,origin='synthetic',clock=time.monotonic,sleep=time.sleep):
    require(origin in ('synthetic','aws_collected_snapshot'),'origin_invalid')
    validate_targets(scope,plan,expected_account,allowed_regions)
    reader=Reader(scope,factory,limits or Limits(),clock=clock,sleep=sleep)
    try:
        reader.identity()
        return Collector(reader,plan,origin).collect()
    except AwsOfflineError as error:
        # Attach only sanitized metadata so CLI can preserve a failed STS attempt.
        reader.audit.update(completed_at=now(),call_count=reader.calls,fatal_error=str(error))
        error.collection_audit=reader.audit
        raise


class MockClient:
    def __init__(self,service,region,script):self.service=service;self.region=region;self.script=script
    def __getattr__(self,operation):
        def call(**params):
            checked(self.script,'MockScriptExhausted');entry=self.script.pop(0)
            checked((entry.get('service'),entry.get('region'),entry.get('operation'),entry.get('params',{}))==(self.service,self.region,operation,params),'MockRequestMismatch')
            if 'error_code' in entry:fail(entry['error_code'])
            return deepcopy(entry.get('response'))
        return call


def mock_factory(script):
    require(isinstance(script,dict) and set(script)=={'schema_version','requests'} and script['schema_version']==1 and isinstance(script['requests'],list),'mock_script_invalid')
    requests=deepcopy(script['requests'])
    return lambda service,region:MockClient(service,region,requests)
