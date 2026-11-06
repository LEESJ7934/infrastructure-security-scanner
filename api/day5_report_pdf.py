"""Korean A4 offline audit renderer using the existing ReportLab design helpers."""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (BaseDocTemplate, Frame, HRFlowable, LongTable, PageBreak,
                               PageTemplate, Paragraph, Spacer, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

from api.report_pdf import INK, LINE, MUTED, NAVY, PALE, TEAL, _body_font, _text
from config_audit.final_report import scrub

STATE_COLORS = {"PASS": "#16705A", "FAIL": "#B4233D", "NEEDS_REVIEW": "#98690B",
                "ERROR": "#B4233D", "NOT_TESTED": "#53647A", "NOT_APPLICABLE": "#53647A"}


def render(snapshot, output_path, *, sample=False):
    """Sample presentation is explicit; the normal report path is unchanged."""
    snapshot = scrub(snapshot)
    if sample and snapshot.get('sample_context', {}).get('synthetic') is not True:
        raise ValueError('sample_context_required')
    font = _body_font()
    width, height = A4
    usable = width - 84
    body = ParagraphStyle("Day5Body", fontName=font, fontSize=9, leading=14, textColor=INK,
                          wordWrap="CJK", splitLongWords=True, spaceAfter=5)
    small = ParagraphStyle("Day5Small", parent=body, fontSize=7.4, leading=10.8, spaceAfter=2)
    label_style = ParagraphStyle("Day5Label", parent=small, keepWithNext=True)
    heading = ParagraphStyle("Day5Heading", parent=body, fontSize=18, leading=26,
                             textColor=NAVY, spaceBefore=4, spaceAfter=14, keepWithNext=True)
    subheading = ParagraphStyle("Day5Subheading", parent=body, fontSize=11, leading=16,
                                textColor=TEAL, spaceBefore=12, spaceAfter=7, keepWithNext=True)
    title = ParagraphStyle("Day5Title", parent=body, fontSize=29, leading=42, textColor=NAVY, spaceAfter=16)
    header = ParagraphStyle("Day5CellHeader", parent=small, textColor=colors.white)
    story = []

    class Document(BaseDocTemplate):
        def afterFlowable(self, flowable):
            if isinstance(flowable, Paragraph) and flowable.style.name == "Day5Heading":
                self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))
        def afterPage(self):
            self.final_page_count = self.page

    def p(value, style=body):
        return Paragraph(_text("미제공" if value is None else value), style)

    def field(label, value):
        story.append(p(label, label_style))
        story.append(p(value))

    def dfield(label, value):
        story.append(Paragraph(f'<font size="8" color="#53647A">{_text(label)}: </font>{_text("미제공" if value is None else value)}', body))

    def status(value):
        color = STATE_COLORS.get(value, "#53647A")
        return Paragraph(f'<font color="{color}">{_text(value or "미제공")}</font>', body)

    def section(number, name):
        story.append(PageBreak())
        story.append(p(f"{number}장. {name}", heading))
        story.append(HRFlowable(width="100%", thickness=1.1, color=TEAL, spaceAfter=12))

    def table(headers, rows, fractions):
        data = [[p(value, header) for value in headers]]
        data.extend([[p(value, small) for value in row] for row in rows])
        if len(data) == 1:
            data.append([p("자료 없음", small) for _ in headers])
        item = LongTable(data, colWidths=[usable*f for f in fractions], repeatRows=1,
                         splitByRow=1, splitInRow=1, hAlign="LEFT", spaceAfter=10)
        item.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                                  ("LINEBELOW", (0, 0), (-1, -1), .35, LINE),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                  ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story.append(item)

    def frame(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, height-12, width, 12, stroke=0, fill=1)
        canvas.setStrokeColor(LINE)
        canvas.line(42, 38, width-42, 38)
        canvas.setFont(font, 7)
        canvas.setFillColor(MUTED)
        footer = 'SAMPLE / 합성 데이터 / 실제 점검 결과 아님' if sample else 'OFFLINE / 저장 자료 기반'
        canvas.drawString(42, 26, f"{footer}  |  {snapshot['report_id'][:12]}")
        canvas.drawRightString(width-42, 26, f"{doc.page:02d}")
        canvas.restoreState()

    doc = Document(str(output_path), pagesize=A4, leftMargin=42, rightMargin=42, topMargin=42,
                   bottomMargin=52,
                   title="SAMPLE / 합성 데이터 / 실제 점검 결과 아님" if sample else "통합 인프라 보안 취약점 진단 결과보고서",
                   author="Synthetic Sample Generator" if sample else "Infrastructure Security Lab",
                   **({'invariant': 1} if sample else {}))
    doc.addPageTemplates(PageTemplate(id="Day5", frames=[Frame(42, 52, usable, height-94,
                                                               leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=frame))
    story += [Spacer(1, 74), p("SAMPLE / 합성 데이터 / 실제 점검 결과 아님" if sample else "INFRASTRUCTURE SECURITY / DAY 5", subheading), Spacer(1, 24),
              p("통합 인프라 보안\n취약점 진단\n결과보고서", title),
              HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=20),
              p("Linux · MySQL · Suricata · ModSecurity · OPNsense", subheading),
              p("SAMPLE / 합성 데이터 / 실제 점검 결과 아님" if sample else "프로젝트 실습 및 오프라인 증적 기반 보고서"),
              p("예시 자산·문서용 IP·시각·라벨만 사용했습니다. 장비 수집이나 증적 검증을 수행하지 않았습니다." if sample else "저장된 과거 자료의 통합·무결성 확인이며 실제 장비의 새로운 진단 결과가 아닙니다."), Spacer(1, 25)]
    field("합성 시나리오 시각 / 버전 (실제 수집 시각 아님)" if sample else "보고서 생성 일시 / 버전", f"{snapshot['generated_at']} / {snapshot['report_version']}")
    field("보고서 ID", snapshot["report_id"])
    field("통합 스냅샷 내용 SHA-256", snapshot["content_sha256"])
    story.append(PageBreak())
    story.append(p("목차", ParagraphStyle("Day5ContentsTitle", parent=heading)))
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("Day5TOC", parent=body, fontSize=11, leading=22, spaceBefore=8)]
    story.append(toc)
    story.append(Spacer(1, 25))
    story.append(p("판정은 원본 채널별로 보존합니다. 수동 PASS와 자동 PASS, 증적 해시 일치와 보안 상태 확인은 서로 다른 사실입니다."))

    section(1, "진단 개요")
    if sample:
        field("공개 샘플 주의", "SAMPLE / 합성 데이터 / 실제 점검 결과 아님. PASS·FAIL 등 예시 라벨은 UI 설명용이며 실제 판정은 모두 NOT_TESTED입니다.")
        table(["합성 자산", "문서용 예약 IP"], list(snapshot['sample_context']['asset_addresses'].items()), [.6, .4])
    field("진단 목적", "합성 입력을 통한 보고서 구조·채널 분리·미검증 표현의 공개 데모입니다." if sample else "인프라 설정 진단 결과와 실습 검증 기록을 통합하고 증적 무결성과 재점검 비교의 한계를 명확히 제시합니다.")
    field("대상 자산", "\n".join(sorted({row['asset_id'] for row in snapshot['details']})))
    field("범위", "가상의 Linux/MySQL/IDS/WAF/방화벽 자산과 문서용 IP만 포함합니다." if sample else "Day2 Linux/MySQL, Day3 Suricata/ModSecurity, Day4 OPNsense의 명시된 저장 결과만 포함합니다.")
    field("진단 방식", "합성 JSON 변환과 미실행 상태의 비교 예시. 실제 파일 무결성·장비·네트워크 검증 없음." if sample else "저장 JSON 변환, 로컬 증적 SHA-256 검사, 명시적 스냅샷 전후 비교. VM·Docker·SSH·API·DB 접속 없음.")
    field("자동·수동 구분", "automatic은 저장 자동 판정, manual은 운영자 수동 기록입니다. PF/로그 원본은 보조 증적이며 새 분석 판정으로 변환하지 않습니다.")
    table(["입력 스냅샷", "일차 / 종류", "입력 상태"],
          [[s['snapshot_id'], f"Day{s['day']} / {s['input_kind']}", s['import_status']] for s in snapshot['inputs']], [.35, .38, .27])
    for source in snapshot['diagnostics']['snapshots']:
        if source['diagnostics']:
            field(source['snapshot_id'] + " / 입력 한계", "; ".join(source['diagnostics']))

    section(2, "진단 결과 요약")
    summary = snapshot['summary']
    field("보고 범위", f"자산 {summary['asset_count']}개 / 고유 자산·항목 {summary['unique_check_count']}개 / 시점별 저장 레코드 {summary['record_count']}개")
    field("집계 원칙", "Day2 최초·재점검을 별도로 표시합니다. 아래 표는 서로 다른 시점·채널이므로 합계를 현재 전체 PASS 수로 해석하면 안 됩니다.")
    statuses = ["PASS", "FAIL", "NEEDS_REVIEW", "ERROR", "NOT_TESTED", "NOT_APPLICABLE"]
    table(["스냅샷 / 자산", "채널"]+statuses,
          [[g['snapshot_id']+"\n"+g['asset_id'], g['channel']]+[g['status_counts'][s] for s in statuses]
           for g in summary['by_snapshot_asset_channel']], [.34, .12]+[.09]*6)
    field("선택 표시", summary['selected_view']['note'])
    field("선택 스냅샷", ", ".join(summary['selected_view']['snapshot_ids']))
    table(["채널"]+statuses,
          [[channel]+[summary['selected_view'][channel][s] for s in statuses] for channel in ('automatic','manual')], [.22]+[.13]*6)
    field("Day4 자동 결과", "SAMPLE: 실제 자동 검사나 수동 검증을 수행하지 않았습니다." if sample else "자료 없음. FW-01 자동 PASS 이력을 재생성하지 않았으며 수동 검증을 자동 결과로 대체하지 않습니다.")
    if sample:
        field("예시 라벨 집계 (실제 판정 아님)", snapshot['sample_context']['illustrative_label_counts'])

    section(3, "세부 진단 결과")
    for record_index, row in enumerate(snapshot['details']):
        story.append(p(f"{row['record_id']}  |  {row['check_id']}  |  {row['snapshot_id']}", subheading))
        dfield("자산 ID", row['asset_id'])
        if sample:
            dfield("합성 예시 라벨 (실제 판정 아님)", row['illustrative_status'])
        definition = row['definition'] or {}
        dfield("진단 항목명 / 기존 규칙 설명", definition.get('check_name'))
        dfield("검사 기준 / 기대 조건", row.get('expected_condition'))
        if not row['definition_is_matching_rule_version'] and definition:
            dfield("참고 규칙 설명 (원본 검사 기준·버전으로 확정하지 않음)", definition.get('expected_condition'))
        dfield("설명·권고 근거", definition.get('source_reference'))
        dfield("원본 관찰값", row['observed_value_note'])
        dfield("확정된 취약 원인·위험 기록", row.get('risk'))
        dfield("기록된 조치 권고", row.get('recommendation') or row.get('recommendation_from_definition'))
        for channel in ('automatic', 'manual'):
            value = row.get(channel)
            if value is None:
                continue
            story.append(p("자동 저장 판정" if channel == 'automatic' else "수동 저장 판정", label_style))
            story.append(status(value['status']))
            dfield("사유 / 범위", f"{value.get('reason') or '미제공'} / {value.get('scope') or '미제공'}")
            dfield("검증 방식 / 규칙 버전", f"{value.get('verification_method') or '미제공'} / {value.get('rule_version') or (row.get('rule_version') if channel=='automatic' else None) or '미제공'}")
            dfield("진단·검토 시각 / 시간 기준", f"{value.get('checked_at') or value.get('verified_at') or '미제공'} / {value.get('time_basis') or ('진단 시각' if channel=='automatic' else '미제공')}")
            dfield("증적 참조", "\n".join(r['reference'] for r in value.get('evidence_references', [])) or '개별 원본 증적 참조 미제공')
            if value.get('tests'):
                table(["시험", "실제 결과", "로그 Action / 규칙"],
                      [[t.get('scenario'), t.get('actual_result'), str(t.get('firewall_action'))+" / "+str(t.get('rule_name'))]
                       for t in value['tests']], [.20, .25, .55])
        dfield("증적 인덱스 연결 수", sum(len(ids) for ids in row.get('evidence_index_ids', {}).values()))
        dfield("미확인 사항", "; ".join(row['unknowns']))
        if record_index < len(snapshot['details'])-1:
            story.append(HRFlowable(width="100%", thickness=.35, color=LINE, spaceBefore=7, spaceAfter=6))

    section(4, "증적 인덱스")
    index = snapshot['diagnostics']['evidence_index']
    field("합성 참조 개수 (실제 검증 없음)" if sample else "실제 재계산 결과", f"고유 로컬 파일 {index['unique_local_files']}개 / 자산·항목·채널별 증적 연결 {len(index['entries'])}건")
    table(["상태", "연결 수"], list(index['counts'].items()), [.70, .30])
    field("기존 보고값과 차이", snapshot['index_reference_difference'])
    field("검증 시각", index['verified_at'])
    field("해석 한계", "NOT_VERIFIED는 독립 기대 해시 부재 또는 읽기 오류를 뜻합니다. 해시 일치는 내용 무결성 확인이며 진위·수집 완전성의 증명이 아닙니다.")
    if sample:
        field("SAMPLE 증적", "참조는 모두 가상의 sample:// URI입니다. 파일 존재·해시 일치 검사를 수행하지 않았으며 VERIFIED는 0건입니다.")
    # One row per association keeps shared-file asset/check relationships visible.
    table(["자산·항목 / 채널", "원본 참조 / 로컬 경로", "SHA-256 / 검증 상태"],
          [[f"{e['asset_id'] or '미배정'}\n{e['check_id'] or '미배정'}\n{e['snapshot_id']} / {e['channel']}",
            f"{e['original_reference']}\n{e['local_path'] or '로컬 경로 없음'}",
            f"actual: {e['actual_sha256'] or '없음'}\nexpected: {e['expected_sha256'] or '없음'}\n{e['status']}\n{e['error'] or ''}"]
           for e in index['entries']], [.25, .39, .36])

    section(5, "조치 전후 재점검 비교")
    comparison = snapshot['comparison']
    field("엄격한 비교 분류", comparison['summary'])
    field("보조 원본 상태 변화 (최종 개선 건수가 아님)", comparison['observed_transition_summary'])
    field("원칙", "원본 상태 변화, 비교 조건, 증적 신뢰도 및 조치 이력은 분리합니다. ERROR/NEEDS_REVIEW에서 PASS로 변한 것만으로 개선 완료가 되지 않습니다.")
    for pair in comparison['pairs']:
        field("명시적 전후 관계", pair['before_snapshot_id']+" -> "+pair['after_snapshot_id'])
        for row in pair['results']:
            story.append(p(row['check_id']+" / "+row['asset_id'], subheading))
            table(["원본 상태 변화", "엄격한 비교 결과", "조치 이력 확인"],
                  [[f"{row['before_status']} -> {row['after_status']}", row['comparison_result'],
                    "확인" if row['remediation_history_confirmed'] else "미확인"]], [.29,.42,.29])
            field("검증 불가·비교 불가 사유", "; ".join(row['unmet_conditions']) or '없음')
            field("증적 신뢰도 (최초 / 재점검)", row['before_evidence']['confidence']+" / "+row['after_evidence']['confidence'])
            field("진단 시각", row['diagnostic_time'])
    field("전후 관계 없는 스냅샷", ", ".join(comparison['unpaired_snapshot_ids']))

    section(6, "미검증 사항 및 후속 조치")
    for number, note in enumerate(snapshot['limitations'], 1):
        field(f"확인 필요 {number:02}", note)
    field("후속 자료", "원래 시험 당시의 범위·수집기·검증 방식 식별자, 독립 기대 해시, 규칙 세대 연속성, 출처가 확인되는 조치 이력이 필요합니다. 과거 자료를 임의로 보완하지 않습니다.")
    field("산출물 무결성", "통합 JSON의 content_sha256은 자기 필드만 제외한 정규 JSON 내용 해시입니다. manifest의 file_sha256은 실제 파일 바이트 해시입니다. manifest는 자기 자신의 해시를 포함하지 않습니다.")
    field("통합 스냅샷 내용 SHA-256", snapshot['content_sha256'])
    doc.multiBuild(story)
    return {"page_count": doc.final_page_count, "font_name": font, "record_count": len(snapshot['details']),
            "report_id": snapshot['report_id'], "content_sha256": snapshot['content_sha256'],
            "visual_validation": "NOT_PERFORMED_BY_RENDERER"}
