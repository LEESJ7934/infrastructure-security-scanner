"""PDF adapter for a reviewed evidence ledger; reuse existing report primitives."""
from collections import Counter
from pathlib import Path
import json
from .kisa_2026 import catalog, STATUSES


def write_pdf(report, destination):
    from api.report_pdf import _body_font, _text, NAVY, PALE, LINE
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, LongTable, TableStyle, KeepTogether
    rows = report.get('results', [])
    if (report.get('report_kind') != 'REVIEWED_CROSS_ENVIRONMENT_EVIDENCE_LEDGER'
            or len(rows) != 16 or {r['kisa_id'] for r in rows} != {r['id'] for r in catalog()['items']}
            or report.get('scope_denominator') != 16):
        raise ValueError('selected_ledger_required')
    counts = Counter(r['status'] for r in rows)
    if (set(report['summary']) != set(STATUSES) or any(r['status'] not in STATUSES for r in rows)
            or any(counts[k] != v for k, v in report['summary'].items())
            or any(r['status'] == 'PASS' and r.get('source_kind') != 'VERIFIED_LAB' for r in rows)
            or report['verified_lab_pass'] != counts['PASS']
            or report['verified_lab_pass_percent'] != 100 * counts['PASS'] / 16):
        raise ValueError('selected_ledger_summary_mismatch')
    font = _body_font()
    body = ParagraphStyle('KisaBody', fontName=font, fontSize=9, leading=13, spaceAfter=6, wordWrap='CJK')
    title = ParagraphStyle('KisaTitle', parent=body, fontSize=19, leading=26, textColor=NAVY, spaceAfter=12)
    head = ParagraphStyle('KisaHead', parent=body, fontSize=12, leading=17, textColor=NAVY,
                          spaceBefore=12, spaceAfter=8, keepWithNext=True)
    cell = ParagraphStyle('KisaCell', parent=body, fontSize=8, leading=11)
    def p(value, style=body):
        return Paragraph(_text(value), style)
    def table(data, widths):
        t = LongTable([[p(v, cell) for v in row] for row in data], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.HexColor('#D8E8F2')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),('GRID',(0,0),(-1,-1),.3,LINE),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
        return t
    story = [p('KISA 2026 선정 범위 진단 결과', title),
        p(f"격리 LAB 실측 PASS {counts['PASS']}/16 ({report['verified_lab_pass_percent']}%)", head),
        p('100% 목표 미달성. 서로 다른 일회용 Linux/Windows 환경의 검토된 증적 대장이다. 고객사 진단, 전체 KISA 준수 또는 인증을 뜻하지 않는다.'),
        p('공식 PDF 873쪽 직접 대조. 일반 권고를 기준으로 별도 개인 LAB 프로파일을 적용했다.'),
        p('구현 커밋: '+report['implementation_commit']),
        table([['상태','개수','해석']]+[[s,n,'실측 원본 검토' if s=='PASS' else '실측 미완료' if s=='NOT_TESTED' else 'PASS에 합산하지 않음'] for s,n in report['summary'].items()], [100,50,361]),
        p('공식 항목별 결과', head),
        table([['ID / 쪽','점검 항목','자산','상태']]+[[r['kisa_id']+' / '+str(r['page']),r['title'],', '.join(r['assets']),r['status']] for r in rows],[65,280,90,76])]
    for row in rows:
        block = [p(row['kisa_id']+' | '+row['status'],head)]
        if row['status']=='PASS':
            block += [p('조치 전: '+json.dumps(row['before'],ensure_ascii=False)),
                      p('조치 후: '+json.dumps(row['after'],ensure_ascii=False)),
                      p('변화: '+row['transition']),p('원시 수집 시각: '+row['collected_at']),
                      p('실행 / 아티팩트: '+str(row['run_id'])+' / '+str(row['artifact_id'])),
                      p('증적: '+row['evidence_url']),p('원본 파일: '+', '.join(row['raw_files']))]
            if row['kisa_id'] == 'U-18':
                block.insert(3,p('파일 권한(8진수): 0666 → 0400. JSON의 mode는 원본 정수 438 → 256이다.'))
        block += [p('한계: '+row['limitation'])]
        story.append(KeepTogether(block))
    story += [p('구현·검증과 남은 작업',head),
        p('16개 정규화 조건 판정 지원, 실제 신규 수집 경로는 Linux 2개와 Windows 4개. WEB/WAS·MySQL·보안장비·AWS의 전체 조건 실측 10개는 미완료다.'),
        p('Codex가 코드·문서 작성과 자동 Actions 실습을 수행했다. 사용자가 직접 수행한 실습 이력과 혼동하지 않는다. 합성 테스트의 성공은 실측 PASS가 아니다.'),
        p('전체 로컬 회귀 1,328개 실행: 실패 0, 기존 환경 의존 skip 22개. 최신 원격 CI 및 main 병합 결과는 PR #5와 별도 최종 전달 기록에서 확인한다.'),
        p('https://github.com/LEESJ7934/infrastructure-security-scanner/pull/5'),
        p('실행 절차: docs/kisa-2026-retest-runbook.md / 면접 16개 사례: docs/kisa-2026-interview.md')]
    for limitation in report['limitations']:
        story.append(p(limitation))
    def footer(canvas, doc):
        canvas.setFont(font,8)
        canvas.drawString(42,24,'Infrastructure Security Scanner | Personal LAB | KISA 2026')
        canvas.drawRightString(A4[0]-42,24,str(doc.page))
    SimpleDocTemplate(destination if hasattr(destination,'write') else str(destination), pagesize=A4,
        leftMargin=42,rightMargin=42,topMargin=42,bottomMargin=40).build(story,onFirstPage=footer,onLaterPages=footer)
