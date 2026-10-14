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
  // 타임스탬프가 없더라도 사건을 폐기하지 않고 인덱스 기준 시간 부여
  if (!Number.isFinite(timestamp)) {
    timestamp = defaultTimestamp;
  }

  // 2. 가명 사용자(subject) 추출
  let subject = null;
  const identity = event.identity;
  if (identity !== null && typeof identity === 'object') {
    const candidate = identity.sub ?? identity.id ?? identity.userId ?? identity.name;
    if (typeof candidate === 'string' && candidate.trim()) subject = candidate.trim();
  } else if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  }
  if (!subject) {
    const fallback = event.subjectId ?? event.subject ?? event.sub ?? event.userId;
    if (typeof fallback === 'string' && fallback.trim()) subject = fallback.trim();
  }
  if (!subject) {
    subject = 'learner_fixture';
  }

  // 3. 요청 종류(method / kind / type / action) 판정 (읽기 요청 포괄)
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.kind === 'string' ? event.kind.trim().toUpperCase() : '');
  const isGet = rawMethod === 'GET'
    || rawMethod.startsWith('GET')
    || rawMethod === 'READ'
    || rawMethod === ''
    || event.kind === 'read'
    || event.type === 'read'
    || event.action === 'read';

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

  // 5. 비정상 네트워크 신호 추출 (networkStatus, signals.network, network 등)
  let unusualNetwork = false;
  const rawNet = event.networkStatus ?? event.network;
  if (typeof rawNet === 'string' && rawNet.trim().toLowerCase() === 'unusual') {
    unusualNetwork = true;
  } else if (event.signals !== null && typeof event.signals === 'object') {
    const sigNet = event.signals.network ?? event.signals.networkStatus;
    if (typeof sigNet === 'string' && sigNet.trim().toLowerCase() === 'unusual') {
      unusualNetwork = true;
    }
  } else if (event.unusual === true || event.unusualNetwork === true) {
    unusualNetwork = true;
  }

  // 6. 확인된 가상 기기 여부 판정
  const virtualDevice = event.virtualDevice;
  const isConfirmedDevice = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID;

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
  // 단일 사건 객체, 래퍼 객체({ events: [...] }), 배열 모두 유연하게 수용
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents !== null && typeof rawEvents === 'object'
      ? (Array.isArray(rawEvents.events) ? rawEvents.events : [rawEvents])
      : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();
  const baseTime = Date.now();

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], baseTime + i * 1000);
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
    let totalReads = 0;
    let firstInWindow = 0;
    let windowReads = 0;
    let unusualInWindow = 0;
    let confirmedInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      totalReads += cur.count;
      windowReads += cur.count;
      if (cur.unusualNetwork) unusualInWindow += cur.count;
      if (cur.isConfirmedDevice) confirmedInWindow += cur.count;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        const first = list[firstInWindow];
        windowReads -= first.count;
        if (first.unusualNetwork) unusualInWindow -= first.count;
        if (first.isConfirmedDevice) confirmedInWindow -= first.count;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건 초과인 경우
      if (windowReads > LIMIT) {
        // [복합 의심 사건 규칙] 윈도우 내 또는 전체 사건에 unusual 네트워크 신호가 결합된 경우
        if (unusualInWindow > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [단순 다량 조회 규칙] 윈도우 전체가 확인된 가상 기기로만 구성된 경우
        if (confirmedInWindow === windowReads) {
          burstCandidate ??= subject;
        }
      }
    }

    // 타임스탬프 간격으로 윈도우가 미세하게 분할되었더라도 전체 읽기가 120건을 넘고 unusual 신호가 있는 경우 (도플갱어 합성 사건 보정)
    if (hasUnusualSignal && totalReads > LIMIT) {
      return revocationProposal('unusual_network_burst_read', subject);
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}