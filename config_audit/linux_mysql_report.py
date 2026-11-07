"""Phase2 PDF adapter; reuse Day5 fonts and escaping, not its actual data."""
from .collectors.linux_mysql_lab import as_snapshot


def write_pdf(report, output):
    from api.report_pdf import _body_font, _text, NAVY, PALE, LINE
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, LongTable, TableStyle, PageBreak, KeepTogether
    font = _body_font()
    body = ParagraphStyle('LMBody', fontName=font, fontSize=9, leading=13, spaceAfter=6, wordWrap='CJK')
    title = ParagraphStyle('LMTitle', parent=body, fontSize=19, leading=26, spaceAfter=12, textColor=NAVY)
    head = ParagraphStyle('LMHead', parent=body, fontSize=12, leading=17, spaceBefore=10, textColor=NAVY)
    cell = ParagraphStyle('LMCell', parent=body, fontSize=8, leading=12)
    def p(value, style=body): return Paragraph(_text(value), style)
    def table(rows):
        table = LongTable([[p(v, cell) for v in row] for row in rows], colWidths=[95, 93, 66, 257], repeatRows=1)
        table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#D8E8F2')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PALE]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), .3, LINE), ('TOPPADDING', (0,0), (-1,-1), 6), ('BOTTOMPADDING', (0,0), (-1,-1), 6)]))
        return table
    label = '합성 테스트 전용 - 실제 컨테이너 진단 결과 아님' if report['origin'] == 'synthetic' else '실행 전 준비 - 실제 진단 미수행' if report['bundle'] is None else '사용자 로컬 Docker LAB 읽기 전용 진단'
    story = [p('LINUX / MYSQL SECURITY LAB', title), p(label, head),
        p('Internal personal LAB criteria; no KISA certification claim.'),
        p('Generated: ' + report['generated_at']), p('Collected: ' + (report['bundle']['collected_at'] if report['bundle'] else 'NOT_TESTED')),
        p('Rule version: ' + report['rule_version']), p('Summary: ' + str(report['summary'])),
        table([['Check', 'Product / version', 'Status', 'Internal LAB criterion']] + [[r['check_id'], r['product'] + ' / ' + str(r['version'] or 'unknown'), r['status'], r['expected_condition']] for r in report['results']]),
        PageBreak(), p('OBSERVATIONS AND RETEST', title)]
    if report['bundle'] is not None and report['bundle'].get('capture_context') == 'new_reproduction_not_historical_baseline':
        story.insert(2, p('새로 재현한 격리 LAB 증적 - 과거 최초 원본 증적이 아님', head))
    if report.get('comparison', {}).get('status') == 'UNAVAILABLE':
        story.insert(2, p('Baseline unavailable: current snapshot only; no improvement claim.'))
    changes = {r['check_id']: r for r in report.get('comparison', {}).get('results', [])}
    def shown(row, value):
        if row['check_id'] == 'LINUX-LAB-003' and isinstance(value, list):
            return '; '.join(v['path'] + ' mode=' + format(v['mode'], '04o') + ' uid=' + str(v['uid'])
                + ' regular=' + str(v['regular']) + ' symlink=' + str(v['symlink']) + ' group_ok=' + str(v['group_approved']) for v in value)
        return str(value)
    for row in report['results']:
        block = [p(row['check_id'] + ' | ' + row['status'], head), p('Observed: ' + shown(row, row['observed_value'])),
            p('Method: ' + row['verification_method']), p('Recommendation: ' + row['recommendation'])]
        if row['check_id'] in changes:
            c = changes[row['check_id']]
            block += [p('Before: ' + shown(row, c['before_values'])), p('After: ' + shown(row, c['after_values'])),
                p(c['before_status'] + ' -> ' + c['after_status'] + ' | ' + c['comparison_result'])]
        story.append(KeepTogether(block))
    story += [p('SCOPE AND LIMITATIONS', head),
        p('Linux container settings only; not a full OS/host audit. SSH scope is root/loopback. Service check covers the LAB demo TCP9000 only.'),
        p('The rsyslog check verifies configuration and daemon, not actual event delivery. The MySQL secure-transport variable is not proof of a TCP TLS handshake or certificate validation.'),
        p('Privilege assessment is limited to lab_app@localhost. Unknown roles or grant syntax prevent PASS. Measured hashes identify bytes, not source authenticity.'),
        p('Synthetic transitions never establish actual remediation. Original settings, passwords, keys, raw grants and access logs are not included.')]
    def footer(canvas, doc):
        canvas.setFont(font, 8); canvas.drawString(42, 24, 'Infrastructure Security Scanner | Personal LAB')
        canvas.drawRightString(A4[0]-42, 24, str(doc.page))
    SimpleDocTemplate(output if hasattr(output, 'write') else str(output), pagesize=A4, leftMargin=42, rightMargin=42, topMargin=36, bottomMargin=40).build(story, onFirstPage=footer, onLaterPages=footer)


def common_snapshot(report, identifier): return as_snapshot(report, identifier).to_dict()
