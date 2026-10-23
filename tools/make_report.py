#!/usr/bin/env python3
"""Builds test-results/report.html from the GoogleTest XML and the end-to-end output."""

import html
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# What each test checks, shown next to its result.
DESCRIPTIONS = {
    "Decode.EthernetIpv4Tcp": "Ethernet → IPv4 → TCP 헤더 필드와 페이로드 추출",
    "Decode.EthernetPaddingIsNotPayload": "60바이트 최소 프레임의 패딩이 TCP 페이로드로 새지 않음",
    "Decode.VlanTagged": "802.1Q VLAN 태그가 붙은 프레임 디코딩",
    "Decode.RawIp": "링크 계층 없는 Raw IPv4 캡처 디코딩",
    "Decode.SnaplenCutIsTruncated": "snaplen으로 잘린 패킷을 Truncated로 판별",
    "Decode.RejectsNonTcpAndFragments": "UDP, ARP, IP 단편을 TCP로 오인하지 않음",
    "Decode.BadTcpDataOffsetIsMalformed": "잘못된 TCP data offset을 Malformed로 거부",
    "ReassemblyTest.InOrderBothDirections": "3-way 핸드셰이크 후 양방향 스트림 전달",
    "ReassemblyTest.OutOfOrderIsReordered": "뒤바뀐 순서로 온 세그먼트를 재정렬",
    "ReassemblyTest.RetransmissionIsDeliveredOnce": "재전송된 세그먼트를 한 번만 전달",
    "ReassemblyTest.PartialOverlapIsTrimmed": "경계가 다른 재전송의 겹친 부분을 잘라냄",
    "ReassemblyTest.OverlappingPendingSegments": "버퍼에 쌓인 세그먼트끼리 겹치는 경우",
    "ReassemblyTest.SequenceWraparound": "시퀀스 번호가 2^32를 넘어 0으로 돌아가는 경우",
    "ReassemblyTest.FinFromBothSidesClosesFlow": "양쪽 FIN으로 연결 종료",
    "ReassemblyTest.FinWaitsForMissingData": "FIN이 먼저 와도 빠진 데이터를 기다린 뒤 종료",
    "ReassemblyTest.ResetClosesImmediately": "RST로 즉시 종료",
    "ReassemblyTest.MidstreamPickupGuessesServerByPort": "핸드셰이크 없이 중간부터 잡힌 연결의 방향 추정",
    "ReassemblyTest.StrayAckDoesNotCreateFlow": "의미 없는 ACK/FIN으로 흐름을 만들지 않음",
    "ReassemblyTest.PortReuseStartsNewConnection": "같은 포트 쌍의 새 SYN을 새 연결로 처리",
    "ReassemblyTest.HandlerCanStopDelivery": "파서가 거부하면 버퍼링을 멈춤",
    "ReassemblyTest.IdleTimeoutClosesFlow": "유휴 타임아웃으로 연결 정리",
    "ReassemblyTest.CloseReportsGapBeforeBufferedData": "종료 시 빈 구간을 갭으로 보고하고 남은 데이터 전달",
    "ReassemblyTest.RandomisedReorderingReproducesStream": "속성 테스트: 무작위 재배열과 재분할 재전송 20KB가 원본과 일치",
    "SmallBufferTest.PendingLimitDeclaresGap": "버퍼 상한을 넘으면 빈 구간을 갭으로 판정",
    "HttpTest.SimpleExchange": "기본 GET/200 요청과 응답 필드 추출",
    "HttpTest.ByteAtATime": "1바이트씩 쪼개진 입력 + chunked 확장/트레일러",
    "HttpTest.PipelinedRequestsMatchResponsesInOrder": "파이프라이닝된 요청과 응답 순서 매칭",
    "HttpTest.HeadResponseHasNoBody": "HEAD 응답은 Content-Length가 있어도 본문 없음",
    "HttpTest.NotModifiedAndContinue": "100 Continue 건너뛰기, 304 본문 없음",
    "HttpTest.BodyDelimitedByClose": "길이 헤더 없는 응답을 연결 종료까지 읽음",
    "HttpTest.UnansweredRequestOnClose": "응답 없이 끊긴 요청을 no_response로 기록",
    "HttpTest.TruncatedResponseIsIncomplete": "본문이 덜 온 응답을 incomplete로 기록",
    "HttpTest.GapInsideBodyKeepsFraming": "본문 중간의 갭에도 다음 요청 경계 유지",
    "HttpTest.GapInHeadersStopsParsing": "헤더 중간의 갭에서는 안전하게 파싱 중단",
    "HttpTest.GapAfterRequestIsReported": "갭으로 끊긴 요청을 flags와 함께 기록",
    "HttpTest.SmugglingIndicatorsAreFlagged": "CL+TE 동시 사용(요청 스머글링 징후) 표시",
    "HttpTest.ConflictingContentLengthStops": "서로 다른 Content-Length가 여러 개면 중단",
    "HttpTest.HeaderTooLarge": "64KB를 넘는 헤더 거부",
    "HttpTest.NonHttpStopsWithoutRecords": "HTTP가 아닌 데이터는 기록하지 않음",
    "HttpTest.WebSocketUpgradeStops": "101 Switching Protocols 이후 파싱 중단",
    "PipelineTest.HttpOnNonStandardPortIsDetectedByContent": "9999번 포트의 HTTP를 내용으로 판별 (디코더부터 전체 경로)",
    "PipelineTest.ServerFirstProtocolIsIgnored": "서버가 먼저 말하는 SSH 연결 무시",
    "Json.EscapesControlAndQuotes": "JSON 제어 문자와 따옴표 이스케이프",
    "Json.KeepsValidUtf8AndReplacesInvalidBytes": "한글은 유지하고 잘못된 UTF-8은 U+FFFD로 치환",
    "Format.Timestamp": "타임스탬프와 IP 문자열 형식",
}

AREAS = [
    ("Decode", "패킷 디코더"),
    ("ReassemblyTest", "TCP 재조립"),
    ("SmallBufferTest", "TCP 재조립 (버퍼 상한)"),
    ("HttpTest", "HTTP 파서"),
    ("PipelineTest", "전체 파이프라인"),
    ("Json", "로그 출력"),
    ("Format", "로그 출력"),
]

CSS = """
:root{--bg:#f7f8fa;--card:#fff;--text:#1d2330;--muted:#5d6675;--line:#e3e6eb;
--pass:#1a7f4b;--pass-bg:#e6f4ec;--fail:#b42318;--fail-bg:#fdecea;--accent:#2f5fb3}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#111418;--card:#1a1e24;
--text:#e6e9ee;--muted:#9aa3b0;--line:#2a3039;--pass:#4cc38a;--pass-bg:#16301f;--fail:#ff7b72;
--fail-bg:#3a1a18;--accent:#7aa2f7}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,"Segoe UI","Malgun Gothic",sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile .v{font-size:26px;font-weight:700}.tile .k{color:var(--muted);font-size:13px}
.ok{color:var(--pass)}.bad{color:var(--fail)}
.bar{height:10px;border-radius:5px;background:var(--fail-bg);overflow:hidden;margin:16px 0 4px}
.bar>div{height:100%;background:var(--pass)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
code{font:12.5px ui-monospace,Consolas,monospace}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.badge.pass{background:var(--pass-bg);color:var(--pass)}.badge.fail{background:var(--fail-bg);color:var(--fail)}
.num{text-align:right;font-variant-numeric:tabular-nums}
pre{white-space:pre-wrap;color:var(--fail);margin:6px 0 0;font-size:12px}
"""


def esc(s):
    return html.escape(str(s))


def load_unit(path):
    root = ET.parse(path).getroot()
    cases = []
    for suite in root.iter("testsuite"):
        for tc in suite.iter("testcase"):
            failures = [f.get("message", "") for f in tc.findall("failure")]
            cases.append({
                "suite": suite.get("name"),
                "name": tc.get("name"),
                "time_ms": float(tc.get("time", 0)) * 1000,
                "failures": failures,
            })
    return root, cases


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "test-results")
    root, cases = load_unit(out / "unit.xml")
    passed = sum(1 for c in cases if not c["failures"])
    total = len(cases)
    failed = total - passed

    e2e = []
    if (out / "e2e.jsonl").exists():
        e2e = [json.loads(l) for l in (out / "e2e.jsonl").read_text(encoding="utf-8").splitlines() if l]
    stats = {}
    if (out / "e2e_stats.json").exists():
        stats = json.loads((out / "e2e_stats.json").read_text(encoding="utf-8").strip() or "{}")

    parts = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Test Report</title><style>{CSS}</style></head><body><main>"]
    parts.append("<h1>Network_Traffic_Analysis 테스트 결과</h1>")
    parts.append(f"<p class='sub'>실행 시각 {esc(root.get('timestamp', ''))} · "
                 f"Debug 빌드 + AddressSanitizer/UBSan · Ubuntu 24.04 컨테이너</p>")

    status_cls = "ok" if failed == 0 else "bad"
    parts.append("<div class='tiles'>")
    parts.append(f"<div class='tile'><div class='v {status_cls}'>{passed} / {total}</div>"
                 f"<div class='k'>단위 테스트 통과</div></div>")
    parts.append(f"<div class='tile'><div class='v {'bad' if failed else ''}'>{failed}</div>"
                 f"<div class='k'>실패</div></div>")
    parts.append(f"<div class='tile'><div class='v'>{float(root.get('time', 0)) * 1000:.0f} ms</div>"
                 f"<div class='k'>전체 실행 시간</div></div>")
    parts.append(f"<div class='tile'><div class='v'>{len(e2e)}</div>"
                 f"<div class='k'>실제 캡처에서 추출한 HTTP 이벤트</div></div>")
    parts.append("</div>")
    pct = 100 * passed / total if total else 0
    parts.append(f"<div class='bar'><div style='width:{pct:.1f}%'></div></div>")

    parts.append("<h2>1. 단위 테스트 (GoogleTest)</h2>")
    seen_areas = []
    for prefix, area in AREAS:
        if area not in seen_areas:
            seen_areas.append(area)
    for area in seen_areas:
        prefixes = [p for p, a in AREAS if a == area]
        rows = [c for c in cases if c["suite"] in prefixes]
        if not rows:
            continue
        ok = sum(1 for c in rows if not c["failures"])
        parts.append(f"<h3>{esc(area)} <span class='badge {'pass' if ok == len(rows) else 'fail'}'>"
                     f"{ok}/{len(rows)}</span></h3>")
        parts.append("<div class='card'><table><tr><th>결과</th><th>테스트</th>"
                     "<th>확인하는 내용</th><th class='num'>시간</th></tr>")
        for c in rows:
            full = f"{c['suite']}.{c['name']}"
            badge = ("<span class='badge pass'>PASS</span>" if not c["failures"]
                     else "<span class='badge fail'>FAIL</span>")
            fail_text = "".join(f"<pre>{esc(f)}</pre>" for f in c["failures"])
            parts.append(f"<tr><td>{badge}</td><td><code>{esc(c['name'])}</code></td>"
                         f"<td>{esc(DESCRIPTIONS.get(full, ''))}{fail_text}</td>"
                         f"<td class='num'>{c['time_ms']:.0f} ms</td></tr>")
        parts.append("</table></div>")

    parts.append("<h2>2. 실제 트래픽 End-to-End</h2>")
    parts.append("<p class='sub'>컨테이너 안에서 Python HTTP 서버를 띄우고 요청을 보내는 동안 tcpdump로 "
                 "루프백을 캡처한 뒤, 그 pcap을 <code>netaudit-agent -r</code>로 분석한 결과입니다.</p>")
    if e2e:
        parts.append("<div class='card'><table><tr><th>Method</th><th>URI</th><th class='num'>Status</th>"
                     "<th class='num'>응답 본문</th><th class='num'>응답 지연</th><th>User-Agent</th>"
                     "<th>Flags</th></tr>")
        for r in e2e:
            delay = r.get("response_delay_us")
            parts.append(
                f"<tr><td><code>{esc(r.get('method', ''))}</code></td><td><code>{esc(r.get('uri', ''))}</code></td>"
                f"<td class='num'>{esc(r.get('status', ''))}</td>"
                f"<td class='num'>{r.get('resp_body_bytes', 0):,} B</td>"
                f"<td class='num'>{'' if delay is None else f'{delay / 1000:.2f} ms'}</td>"
                f"<td>{esc(r.get('user_agent', ''))}</td><td>{esc(r.get('flags', ''))}</td></tr>")
        parts.append("</table></div>")
    if stats:
        labels = [("packets", "패킷"), ("flows", "TCP 연결"), ("delivered_bytes", "재조립된 바이트"),
                  ("retransmitted_bytes", "재전송 바이트"), ("out_of_order_segments", "순서 뒤바뀜"),
                  ("gap_events", "갭"), ("events", "기록된 이벤트")]
        parts.append("<h3>처리 통계</h3><div class='tiles'>")
        for key, label in labels:
            parts.append(f"<div class='tile'><div class='v'>{stats.get(key, 0):,}</div>"
                         f"<div class='k'>{label}</div></div>")
        parts.append("</div>")

    parts.append("</main></body></html>")
    (out / "report.html").write_text("".join(parts), encoding="utf-8")
    print(f"wrote {out / 'report.html'} ({passed}/{total} passed, {len(e2e)} e2e events)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
