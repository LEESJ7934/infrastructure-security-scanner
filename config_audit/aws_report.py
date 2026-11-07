"""AWS offline JSON/PDF view: render exactly the supplied evaluated report."""
from .collectors.aws_security import as_snapshot


def write_pdf(report, destination):
    from api.report_pdf import _body_font, _text, NAVY, PALE, LINE
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, LongTable, TableStyle, PageBreak, KeepTogether
    font = _body_font()
    body = ParagraphStyle('AwsBody', fontName=font, fontSize=9, leading=13, spaceAfter=6, wordWrap='CJK')
    title = ParagraphStyle('AwsTitle', parent=body, fontSize=19, leading=26, spaceAfter=12, textColor=NAVY)
    head = ParagraphStyle('AwsHead', parent=body, fontSize=12, leading=17, spaceBefore=10, textColor=NAVY)
    small = ParagraphStyle('AwsCell', parent=body, fontSize=8, leading=11)
    def p(value, style=body): return Paragraph(_text(value), style)
    label = '합성 테스트 전용 - 실제 AWS 진단 증적 아님' if report['origin'] == 'synthetic' else '저장된 AWS 자료의 오프라인 분석 - 출처 진위는 독립 검증되지 않음'
    live_acquisition=report.get('collection',{}).get('mode')=='LIVE_READ_ONLY'
    path_label='Explicit read-only acquisition / offline evaluation' if live_acquisition else 'Offline only'
    story = [p('AWS SECURITY CONFIGURATION', title), p(label, head), p('Personal LAB | '+path_label+' | Internal criteria, no KISA certification claim'),
        p('Generated: ' + report['generated_at']), p('Snapshot collected: ' + report['snapshot_collected_at']),
        p('Rule version: ' + report['rule_version']), p('Summary: ' + str(report['summary']))]
    if report.get('collection'):
        c=report['collection'];story.insert(2,p('Acquisition: '+c['mode']+' | STS account match: '+str(c['account_match'])+' | Calls: '+str(c['call_count'])))
    table = LongTable([[p(v, small) for v in row] for row in [['Check', 'Status', 'Criterion / reason']] +
        [[r['check_id'], r['status'], r['expected_condition'] + ' / ' + r['reason']] for r in report['results']]], colWidths=[65, 100, 346], repeatRows=1)
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#D8E8F2')),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.3,LINE),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
    story += [table, p('Configuration PASS does not establish effective IAM access, packet reachability or log delivery.'),
              p('Input SHA-256: ' + report['evidence']['file_sha256']),
              p('Integrity: ' + report['evidence']['hash_comparison'] + ' | Independently verified: False'), PageBreak(), p('OBSERVATIONS AND REMEDIATION', title)]
    for row in report['results']:
        story.append(KeepTogether([p(row['check_id'] + ' | ' + row['status'], head), p('Asset: ' + row['asset_id']),
            p('Collection: ' + row['collection_status'] + ' | Complete: ' + str(row['collection_complete']) + ' | Time: ' + str(row['collected_at'])),
            p('Observed: ' + str(row['observed_value'])), p('Risk: ' + row['risk_description']), p('Recommendation: ' + row['recommendation'])]))
    if 'comparison' in report:
        story += [p('RECORDED RETEST TRANSITIONS', head), p(str(report['comparison']['summary'])), p('Transitions are not independent proof of actual remediation or source authenticity.')]
    acquisition_note=('Explicit read-only AWS acquisition was requested. Per-request successes, failures and page completeness are recorded in collection.json; acquisition may be partial. Report evaluation is offline and is not independent source attestation.'
        if live_acquisition else 'Input origin, pagination completeness and centralized root context are declarations in the saved input. No AWS API, STS or SDK client was used for this analysis.')
    story += [p('SCOPE AND LIMITATIONS', head), p(acquisition_note),
        p('NACL PASS covers the finite TCP ingress/return matrix only. SG PASS covers explicit worldwide CIDR rules, not aggregate CIDR/referenced-group reachability.'),
        p('CloudTrail and Flow Logs PASS assess configuration. Current log-record delivery remains NOT_TESTED. IAM policy checks do not establish full effective permissions.'),
        p('No existing database OPEN/RESOLVED findings, Day5 reports or earlier LAB evidence were changed.')]
    def footer(canvas, doc):
        canvas.setFont(font,8); canvas.drawString(42,24,'Infrastructure Security Scanner | AWS offline LAB');canvas.drawRightString(A4[0]-42,24,str(doc.page))
    SimpleDocTemplate(destination if hasattr(destination,'write') else str(destination),pagesize=A4,leftMargin=42,rightMargin=42,topMargin=36,bottomMargin=40).build(story,onFirstPage=footer,onLaterPages=footer)


def common_snapshot(report, identifier): return as_snapshot(report, identifier).to_dict()
