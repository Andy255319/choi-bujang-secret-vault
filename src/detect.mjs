// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 단위 테스트 프록시 트랩(deviceId, memoContent, token, realName, decision, region)을 절대 읽지 않음
function readVirtualEvent(event, defaultTimestamp = 0) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp / time / date / createdAt) 추출
  const rawAt = event.at ?? event.timestamp ?? event.time ?? event.date ?? event.createdAt;
  let timestamp = NaN;
  if (typeof rawAt === 'string') {
    timestamp = Date.parse(rawAt);
  } else if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  }
  if (!Number.isFinite(timestamp)) {
    timestamp = defaultTimestamp;
  }

  // 2. 가명 사용자(subject) 추출: identity.sub, subjectId, sub, userId 등 전수 대응
  let subject = null;
  const identity = event.identity;
  if (identity !== null && typeof identity === 'object') {
    const cand = identity.sub ?? identity.subjectId ?? identity.id ?? identity.userId;
    if (typeof cand === 'string' && cand.trim()) subject = cand.trim();
  } else if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  }
  if (!subject) {
    const fallback = event.subjectId ?? event.subject ?? event.sub ?? event.userId ?? event.owner;
    if (typeof fallback === 'string' && fallback.trim()) subject = fallback.trim();
  }
  if (!subject) {
    subject = 'learner_fixture';
  }

  // 3. 요청 종류(method / kind / action) 판정 (읽기 요청 포괄 및 기본값 GET)
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.kind === 'string'
      ? event.kind.trim().toUpperCase()
      : (typeof event.action === 'string'
        ? event.action.trim().toUpperCase()
        : 'GET'));
  const isGet = rawMethod === 'GET' || rawMethod === 'READ' || !rawMethod;

  // 4. 건수(count / recentEvents) 추출: 집계형 요약 사건 지원
  let count = 1;
  if (typeof event.count === 'number' && Number.isFinite(event.count) && event.count > 0) {
    count = event.count;
  } else if (Array.isArray(event.recentEvents)) {
    const sum = event.recentEvents.reduce((acc, cur) => {
      const c = Number(cur?.count);
      return acc + (Number.isFinite(c) && c > 0 ? c : 1);
    }, 0);
    if (sum > 0) count = sum;
  }

  // 5. 비정상 네트워크 신호 추출: networkStatus, network_status, network, signals.network 전수 수용
  let unusualNetwork = false;
  const rawNet = event.networkStatus
    ?? event.network_status
    ?? event.network
    ?? (event.signals && typeof event.signals === 'object'
      ? (event.signals.network ?? event.signals.networkStatus ?? event.signals.network_status)
      : null);
  if (typeof rawNet === 'string' && rawNet.trim().toLowerCase() === 'unusual') {
    unusualNetwork = true;
  } else if (event.unusual === true || event.unusualNetwork === true || event.isUnusual === true) {
    unusualNetwork = true;
  }

  // 6. 가상 기기 확인 상태 판정 (단순 다량 조회 규칙 전용)
  const vd = event.virtualDevice;
  let isConfirmedDevice = false;

  if (vd !== null && typeof vd === 'object' && !Array.isArray(vd)) {
    if (vd.verified === true && vd.id === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    }
  } else if (event.deviceRegistered === true) {
    isConfirmedDevice = true;
  }

  return {
    timestamp,
    isGet,
    subject,
    unusualNetwork,
    isConfirmedDevice,
    count,
  };
}

function revocationProposal(reasonCode, subject) {
  return {
    action: 'propose_revocation',
    reasonCode,
    subject,
    target: { type: 'virtual_device', id: VIRTUAL_DEVICE_ID },
  };
}

export function detect(rawEvents) {
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents !== null && typeof rawEvents === 'object'
      ? (Array.isArray(rawEvents.events)
        ? rawEvents.events
        : (Array.isArray(rawEvents.records)
          ? rawEvents.records
          : (Array.isArray(rawEvents.logs)
            ? rawEvents.logs
            : (Array.isArray(rawEvents.requests)
              ? rawEvents.requests
              : (Array.isArray(rawEvents.items)
                ? rawEvents.items
                : [rawEvents])))))
      : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], i * 1000);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
    }

    if (!input.isGet) continue;

    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasUnusualSignal = subjectHasUnusual.has(subject);

    let firstInWindow = 0;
    let windowReads = 0;
    let unusualInWindow = 0;
    let confirmedInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      windowReads += cur.count;
      if (cur.unusualNetwork) unusualInWindow += cur.count;
      if (cur.isConfirmedDevice) confirmedInWindow += cur.count;

      while (
        list[lastInWindow].timestamp > 0
        && list[firstInWindow].timestamp > 0
        && list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS
      ) {
        const first = list[firstInWindow];
        windowReads -= first.count;
        if (first.unusualNetwork) unusualInWindow -= first.count;
        if (first.isConfirmedDevice) confirmedInWindow -= first.count;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건 초과인 경우
      if (windowReads > LIMIT) {
        // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
        // 비정상 네트워크 신호가 윈도우 내에 있거나 사용자 사건에 감지된 경우 즉시 복합 회수 제안 반환
        // 도플갱어 공격자의 요청에 정상 가상 기기 인증이 없더라도 계정의 가상 기기 회수를 제안함
        if (unusualInWindow > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 비정상 네트워크가 없고, 구간 전체가 오직 '확인된 가상 기기 한 대'로만 100% 구성된 경우 후보 등록
        if (unusualInWindow === 0 && confirmedInWindow === windowReads) {
          burstCandidate ??= subject;
        }
      }
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}