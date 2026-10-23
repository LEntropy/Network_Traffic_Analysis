# netaudit-agent

C++17로 작성한 네트워크 트래픽 감사 에이전트입니다. 패킷을 캡처해 TCP 스트림을 재조립하고, 애플리케이션 계층 프로토콜을 해석해 감사 로그(JSON Lines)로 남깁니다.

현재 구현 범위: **pcap 캡처 → IPv4/TCP 디코딩 → TCP 재조립 → 프로토콜 판별 → HTTP/1.x 파서 → JSON 로그**

```
 libpcap ──► decode_frame ──► TcpReassembler ──► ProbingHandler ──► HttpParser ──► EventSink
 (파일/NIC)   Ethernet/VLAN/    순서 뒤바뀜·재전송·    첫 바이트로        요청/응답 매칭     JSON Lines
              SLL/Raw IPv4      겹침·seq 랩어라운드    프로토콜 판별      본문 프레이밍
```

## 설계 요점

- **TCP 재조립** (`src/reassembly.cpp`)
  - 32비트 시퀀스 번호를 ISN 기준 64비트 스트림 오프셋으로 바꿔서, 랩어라운드가 있어도 순서 비교가 단순해집니다.
  - 순서가 뒤바뀐 세그먼트는 오프셋 기준 `std::map`에 버퍼링합니다. 재전송이나 겹치는 구간은 잘라내서 같은 바이트를 두 번 전달하지 않습니다.
  - 버퍼 상한을 넘거나 연결이 닫힐 때까지 빈 구간이 채워지지 않으면 갭으로 판정해 `on_gap`으로 알립니다. 캡처 드롭이 있어도 스트림이 멈추지 않습니다.
  - FIN은 앞쪽 데이터가 모두 도착한 뒤에야 종료로 처리합니다. RST, 유휴 타임아웃, 포트 재사용(새 SYN)도 처리합니다.
- **플러그인형 프로토콜 판별** (`src/dispatcher.cpp`): 포트 번호 대신 연결의 첫 바이트로 프로토콜을 판별합니다. 새 프로토콜은 `ParserFactory{probe, create}`를 하나 등록하기만 하면 추가됩니다.
- **HTTP/1.x 파서** (`src/http_parser.cpp`)
  - 바이트 단위로 쪼개져 들어와도 동작하는 증분 상태 기계입니다. 파이프라이닝된 요청과 응답을 순서대로 짝짓습니다.
  - RFC 9112 본문 규칙을 따릅니다: chunked가 Content-Length보다 우선하고, HEAD·1xx·204·304 응답에는 본문이 없으며, 프레이밍 헤더가 없는 응답은 연결이 닫힐 때까지 읽습니다. 101(Upgrade)과 CONNECT 터널을 만나면 파싱을 멈춥니다.
  - 본문 중간에 갭이 생겨도 남은 길이만 차감해서 다음 요청의 경계를 유지합니다.
  - 요청 스머글링 징후를 `flags`로 남깁니다: `cl_te_conflict`, `conflicting_content_length`, `bad_header_name`, `obs_fold`, `bare_lf`
- **로그 안전성**: 캡처된 임의 바이트 중 잘못된 UTF-8은 U+FFFD로 바꿔서 항상 유효한 JSON만 출력합니다.

## 빌드와 테스트

Docker만 있으면 됩니다. Linux(x86_64, arm64/라즈베리파이)에서 동일하게 빌드됩니다.

```bash
docker build -t netaudit-agent .
```

이미지 빌드 중에 단위 테스트(GoogleTest, 45개)가 실행됩니다. 개발할 때는 ASan/UBSan을 켜고 빌드합니다.

```bash
docker build -t netaudit-dev -f docker/dev.Dockerfile docker
docker run --rm -v "$PWD:/src" -v netaudit-build:/build netaudit-dev bash -c "cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DNETAUDIT_SANITIZE=ON && cmake --build /build && ctest --test-dir /build --output-on-failure"
```

## 사용법

```bash
netaudit-agent -r capture.pcap
netaudit-agent -i eth0 -f "tcp" -o /var/log/netaudit.jsonl
```

라이브 캡처는 `CAP_NET_RAW` 권한이 필요합니다(`docker run --net=host --cap-add NET_RAW --cap-add NET_ADMIN`).

출력 예시(실제 루프백 캡처):

```json
{"type":"http","ts":"2026-10-23T09:12:15.428452Z","client_ip":"127.0.0.1","client_port":50716,"server_ip":"127.0.0.1","server_port":8080,"method":"GET","host":"127.0.0.1:8080","uri":"/missing?q=1","user_agent":"Python-urllib/3.12","req_content_type":"","req_body_bytes":0,"status":404,"resp_content_type":"text/html;charset=utf-8","resp_body_bytes":335,"response_delay_us":328}
{"type":"stats","packets":33,"tcp_segments":33,"flows":3,"delivered_bytes":1229,"retransmitted_bytes":0,"out_of_order_segments":0,"gap_events":0,"events":3}
```

## 테스트 범위

| 영역 | 확인 내용 |
|---|---|
| 디코더 | VLAN, Linux SLL/Raw IP, 이더넷 패딩 제거, snaplen 잘림, IP 단편, 잘못된 data offset |
| 재조립 | 순서 뒤바뀜, 재전송, 부분 겹침, seq 랩어라운드, FIN 대기, RST, 미드스트림 시작, 포트 재사용, 버퍼 상한 갭, 무작위 재배열 속성 테스트(20KB, 재분할 재전송 포함) |
| HTTP | 바이트 단위 입력, chunked + 확장 + 트레일러, 파이프라이닝, HEAD/304/100, close 구분 본문, 갭 처리, 스머글링 징후, 헤더 크기 제한, WebSocket 업그레이드 |
| 파이프라인 | 비표준 포트에서 내용 기반 HTTP 판별, 서버가 먼저 말하는 프로토콜(SSH) 무시 |

## 한계와 다음 단계

- IPv6, IP 단편 재조립 미지원 (단편은 `ip_fragments`로 집계만 함)
- 체크섬 검증 안 함 (송신 호스트 캡처에서는 오프로딩 때문에 체크섬이 비어 있는 경우가 많음)
- 현재 단일 스레드: 다음 단계로 캡처 스레드와 분석 스레드를 분리하고, 흐름 해시 기반으로 샤딩할 예정
- 다음 프로토콜 플러그인: SMTP(발신자, 수신자, 첨부 파일명), MySQL(쿼리문)
- 정책 엔진: 개인정보 패턴 탐지, 도메인 차단 목록
