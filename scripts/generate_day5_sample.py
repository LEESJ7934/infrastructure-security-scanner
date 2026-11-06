"""Reproducible public SAMPLE: no real input, collectors, log files or credentials."""

from collections import Counter
import hashlib
import json
from pathlib import Path

from api.day5_report_pdf import render
from config_audit.comparison import SnapshotRelation, compare_snapshots
from config_audit.evidence_index import STATES, attach_evidence_index, report_bindings
from config_audit.final_report import canonical, content_sha256
from config_audit.reporting import integrate, normalize
from config_audit.statuses import AuditStatus

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TIME = '2026-01-03T00:00:00+00:00'
ASSETS = {'DEMO-LINUX-01': '192.0.2.10', 'DEMO-MYSQL-01': '192.0.2.20',
          'DEMO-IDS-01': '198.51.100.10', 'DEMO-WAF-01': '198.51.100.20', 'DEMO-FW-01': '203.0.113.1'}
DEFINITIONS = {'LAB-SSH-001': 'SSH 빈 비밀번호 정책 예시', 'LAB-SSH-002': 'SSH 직접 루트 로그인 정책 예시',
               'LAB-MYSQL-001': 'LOCAL INFILE 설정 예시', 'LAB-MYSQL-002': '암호화 전송 설정 예시',
               'IDS-01': 'IDS 출력 설정 예시', 'WAF-01': 'WAF 정책 실행 모드 예시',
               'FW-04': '방화벽 규칙 범위 검토 예시', 'FW-05': '로그와 규칙 연계 검토 예시', 'FW-06': '정책 통신 시험 예시'}


def synthetic_inputs():
    """Illustrative labels are deliberately separate from real AuditStatus."""
    inputs = []
    labels = {}
    def check(asset, identifier, snapshot, illustrative, after=False):
        labels[(snapshot, asset, identifier)] = illustrative
        return {'asset_id': asset, 'check_id': identifier, 'rule_version': 'sample-1', 'status': 'NOT_TESTED',
                'execution_id': 'SAMPLE-NOT-EXECUTED', 'checked_at': '2026-01-02T00:00:00+00:00' if after else '2026-01-01T00:00:00+00:00',
                'reason': 'SAMPLE: 실제 검사 미실행', 'scope': 'SYNTHETIC_EXAMPLE_ONLY',
                'diagnostic_source': 'SAMPLE-FIXTURE', 'verification_method': 'not_executed_synthetic_example',
                'evidence_reference': f'sample://not-collected/{asset}/{identifier}.txt'}
    for snapshot, after in (('day2-before', False), ('day2-after', True)):
        document = {}
        for name, asset, prefix in (('ubuntu', 'DEMO-LINUX-01', 'LAB-SSH'), ('mysql', 'DEMO-MYSQL-01', 'LAB-MYSQL')):
            document[name] = {'settings': {}, 'checks': [check(asset, f'{prefix}-{i:03}', snapshot,
                'PASS' if after or i==1 else 'FAIL', after) for i in (1,2)]}
        inputs.append((snapshot, 2, 'results', document))
    inputs.append(('day3-final', 3, 'results', {'results': [
        check('DEMO-IDS-01','IDS-01','day3-final','PASS'), check('DEMO-WAF-01','WAF-01','day3-final','FAIL')]}))
    manual = []
    for identifier, illustrative in (('FW-04','NEEDS_REVIEW'),('FW-05','NEEDS_REVIEW'),('FW-06','PASS')):
        labels[('day4-manual','DEMO-FW-01',identifier)] = illustrative
        manual.append({'check_id':identifier,'reported_status':'NOT_TESTED','verified_at':None,
                       'scope':'SYNTHETIC_EXAMPLE_ONLY','sources':[{'kind':'synthetic_reference',
                       'path':f'sample://not-collected/DEMO-FW-01/{identifier}.txt'}],'tests':[]})
    inputs.append(('day4-manual',4,'manual',{'schema_version':1,'asset_id':'DEMO-FW-01','checks':manual}))
    return inputs, labels


def build_sample():
    inputs, labels = synthetic_inputs()
    report = integrate([normalize(document, day=day, snapshot_id=identifier, input_kind=kind,
                                  source=f'sample://inputs/{identifier}.json')
                        for identifier, day, kind, document in inputs], generated_at=SAMPLE_TIME)
    # URI references have no filesystem base. Keep output portable across OSes.
    for source in report.snapshots:
        for row in source.results:
            for channel in (row.automatic, row.manual):
                if channel:
                    for reference in channel.get('evidence_references', []):
                        reference['relative_to'] = None
    # A declared synthetic index, not execution of the real integrity verifier.
    # No local paths, expected hashes or fake VERIFIED evidence are created.
    entries = []
    for binding in report_bindings(report, include_snapshot_sources=False):
        item = dict(vars(binding))
        reference = item.pop('reference')
        item.update(original_reference=reference, local_path=None, exists=None, actual_sha256=None,
                    status='EXTERNAL_REFERENCE', hash_comparison='NOT_COMPARED', size_bytes=None,
                    verified_at=None, error=None, limitations=['SAMPLE: fictitious reference; no file verification performed'])
        item['evidence_id'] = 'sample-ev-' + hashlib.sha256(canonical(item)).hexdigest()[:20]
        entries.append(item)
    entries.sort(key=lambda item:(item['snapshot_id'],item['asset_id'],item['check_id'],item['channel']))
    index = {'schema_version':1,'verified_at':None,'entries':entries,'counts':{s:sum(e['status']==s for e in entries) for s in STATES},
             'unique_local_files':0,'duplicate_bindings_removed':0,'limitations':['SAMPLE: no actual evidence collected or verified']}
    report = attach_evidence_index(report,index)
    comparison = compare_snapshots(report,[SnapshotRelation('day2-before','day2-after')]).to_dict()
    # All display timestamps belong to the documented fiction, not a capture.
    comparison['generated_at'] = SAMPLE_TIME
    comparison['time_basis'] = 'SYNTHETIC_FIXTURE_CLOCK_NOT_ACTUAL_EXECUTION_TIME'
    details, groups = [], []
    for source in report.snapshots:
        for row in source.results:
            details.append({'record_id':f'RESULT-{len(details)+1:03}', 'snapshot_id':source.snapshot_id, 'day':source.day,
                **row.to_dict(), 'illustrative_status':labels[(source.snapshot_id,row.asset_id,row.check_id)],
                'definition':{'check_name':DEFINITIONS[row.check_id], 'expected_condition':'합성 UI 설명용 기준; 실제 검사에 적용하지 않음',
                              'source_reference':'scripts/generate_day5_sample.py#SYNTHETIC_DEFINITIONS'},
                'definition_is_matching_rule_version':False,'expected_condition':None,'recommendation_from_definition':None,
                'observed_value':None,'observed_value_note':'SAMPLE: 실제 관찰·장비 검사 없음',
                'unknowns':['실제 상태 미검사','원본 로그 없음','독립 기대 해시 없음','조치 이력 없음']})
        for asset in sorted({row.asset_id for row in source.results}):
            for channel in ('automatic','manual'):
                values=[getattr(row,channel) for row in source.results if row.asset_id==asset and getattr(row,channel) is not None]
                if values:
                    counts=Counter(value['status'] for value in values)
                    groups.append({'snapshot_id':source.snapshot_id,'asset_id':asset,'channel':channel,
                                   'status_counts':{s.value:counts[s.value] for s in AuditStatus}})
    selected=[row for row in details if row['snapshot_id']!='day2-before']
    def counts(channel):
        values=Counter(row[channel]['status'] for row in selected if row[channel] is not None)
        return {s.value:values[s.value] for s in AuditStatus}
    data={'schema_version':'day5-offline-final/1','report_id':'sample-'+hashlib.sha256(canonical([i[3] for i in inputs])).hexdigest()[:20],
          'report_version':'SAMPLE-1','generated_at':SAMPLE_TIME,'mode':'SAMPLE_SYNTHETIC_ONLY','completion_status':'SAMPLE_NOT_AUDITED',
          'sample_context':{'synthetic':True,'notice':'SAMPLE / 합성 데이터 / 실제 점검 결과 아님',
                            'timestamps_are_illustrative':True,'operator':'SAMPLE-OPERATOR','asset_addresses':ASSETS,
                            'illustrative_label_counts':dict(Counter(labels.values()))},
          'inputs':[{'snapshot_id':i,'day':d,'input_kind':k,'import_status':'SYNTHETIC_NOT_COLLECTED'} for i,d,k,_ in inputs],
          'synthetic_inputs':[{'snapshot_id':i,'day':d,'input_kind':k,'document':doc} for i,d,k,doc in inputs],
          'diagnostics':report.to_dict(),'comparison':comparison,'details':details,
          'summary':{'asset_count':len(ASSETS),'record_count':len(details),'unique_check_count':len({(r['asset_id'],r['check_id']) for r in details}),
                     'by_snapshot_asset_channel':groups,'selected_view':{'snapshot_ids':['day2-after','day3-final','day4-manual'],
                     'note':'SAMPLE: 실제 판정은 모두 NOT_TESTED. 예시 라벨은 실제 진단 결과가 아닙니다.',
                     'record_count':len(selected),'automatic':counts('automatic'),'manual':counts('manual')}},
          'index_reference_difference':{'note':'SAMPLE: 실제 보고서의 통계와 비교하지 않음'},
          'limitations':['SAMPLE / 합성 데이터 / 실제 점검 결과 아님. 예시 라벨을 실제 PASS·FAIL로 해석하지 않습니다.',
                         '모든 자산·문서용 예약 IP·시각·운영자명은 합성 자료입니다.',
                         '증적 URI는 가상의 예시이며 해시나 실제 파일을 검증하지 않았습니다.',
                         '원본 장비 로그·스크린샷·사용자 경로·인증정보를 읽거나 포함하지 않았습니다.',
                         'PDF 재생성은 폰트와 라이브러리 버전에 따라 페이지 수·파일 해시가 달라질 수 있습니다.']}
    data['content_sha256']=content_sha256(data)
    return data


def generate_sample(output_dir=None):
    directory=Path(output_dir).resolve() if output_dir else ROOT/'examples/day5-demo'
    if directory.is_relative_to(ROOT/'reports') or directory.is_relative_to(ROOT/'evidence'):
        raise ValueError('sample_output_cannot_overwrite_real_artifacts')
    data=build_sample()
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'sample-integrated-report.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    metadata=render(data,directory/'sample-integrated-report.pdf',sample=True)
    return {'output_dir':str(directory),'pages':metadata['page_count'],'records':len(data['details']),
            'content_sha256':data['content_sha256']}


if __name__=='__main__':
    print(json.dumps(generate_sample(),ensure_ascii=False,indent=2))
