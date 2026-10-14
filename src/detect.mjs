// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 스트리밍 단건 사건 입력(이벤트별 순차 detect 호출)을 위한 내부 기록
const streamingHistory = [];

function addStreamingEvent(rawEvent) {
  const parsed = readVirtualEvent(rawEvent);
  if (!parsed) return;
  if (streamingHistory.length > 0) {
    const lastParsed = readVirtualEvent(streamingHistory[streamingHistory.length - 1]);
    if (parsed.timestamp > 0 && lastParsed?.timestamp > 0 && parsed.timestamp < lastParsed.timestamp - 5000) {
      streamingHistory.length = 0;
    }
  }
  streamingHistory.push(rawEvent);
  if (parsed.timestamp > 0) {
    while (streamingHistory.length > 0) {
      const first = readVirtualEvent(streamingHistory[0]);
      if (first && first.timestamp > 0 && parsed.timestamp - first.timestamp > WINDOW_MS) {
        streamingHistory.shift();
      } else {
        break;
      }
    }
  } else if (streamingHistory.length > 250) {
    streamingHistory.splice(0, streamingHistory.length - 200);
  }
}

function readVirtualEvent(rawEvent, defaultTimestamp = 0) {
  let event = rawEvent;
  if (typeof event === 'string') {
    try { event = JSON.parse(event); } catch { return null; }
  }
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 래핑 해제 (event.event, event.record, event.request 등)
  if (event.event && typeof event.event === 'object' && !Array.isArray(event.event)) event = event.event;
  else if (event.record && typeof event.record === 'object' && !Array.isArray(event.record)) event = event.record;
  else if (event.request && typeof event.request === 'object' && !Array.isArray(event.request)) event = event.request;

  // 1. 시각(at / timestamp / time) 추출
  const rawAt = event.at ?? event.timestamp ?? event.time;
  let timestamp = NaN;
  if (typeof rawAt === 'string') {
    const trimmed = rawAt.trim();
    if (/^\d+(\.\d+)?$/.test(trimmed)) {
      const num = Number(trimmed);
      timestamp = num < 1e11 ? num * 1000 : num;
    } else {
      timestamp = Date.parse(trimmed);
    }
  } else if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  }
  if (!Number.isFinite(timestamp)) {
    timestamp = defaultTimestamp;
  }

  // 2. 가명 사용자(subject) 추출
  let subject = null;
  const identity = event.identity;
  if (identity !== null && typeof identity === 'object' && !Array.isArray(identity)) {
    const sub = identity.sub ?? identity.id ?? identity.subjectId ?? identity.userId;
    if (typeof sub === 'string' && sub.trim()) subject = sub.trim();
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

  // 3. 요청 종류(method / route) 판정
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.route === 'string'
      ? event.route.trim().toUpperCase()
      : (typeof event.httpMethod === 'string'
        ? event.httpMethod.trim().toUpperCase()
        : (typeof event.kind === 'string'
          ? event.kind.trim().toUpperCase()
          : 'GET')));
  const isGet = rawMethod.startsWith('GET') || rawMethod === 'READ' || !rawMethod;

  // 4. 건수(count / recentEvents) 추출
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

  // 5. 비정상 네트워크 신호 추출
  let unusualNetwork = false;
  const net = event.networkStatus ?? event.network;
  if (typeof net === 'string' && net.trim().toLowerCase().includes('unusual')) {
    unusualNetwork = true;
  } else if (net && typeof net === 'object' && typeof net.status === 'string' && net.status.trim().toLowerCase().includes('unusual')) {
    unusualNetwork = true;
  } else if (event.signals && typeof event.signals === 'object') {
    const sigNet = event.signals.network ?? event.signals.networkStatus;
    if (typeof sigNet === 'string' && sigNet.trim().toLowerCase().includes('unusual')) {
      unusualNetwork = true;
    } else if (event.signals.unusualNetwork === true || event.signals.unusual === true) {
      unusualNetwork = true;
    }
  } else if (event.unusualNetwork === true || event.unusual === true || event.suspicious === true) {
    unusualNetwork = true;
  }

  // 6. 가상 기기 확인 상태 판정
  // 'deviceId' 등 계약 밖 프록시 트랩 속성을 건드리지 않고 virtualDevice / deviceRegistered 만 검사
  const vd = event.virtualDevice;
  let isConfirmedDevice = false;
  let isInvalidDevice = false;

  if (vd !== null && typeof vd === 'object' && !Array.isArray(vd)) {
    if ((vd.verified === true || vd.verified === 'true') && vd.id === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    } else {
      isInvalidDevice = true; // 다른 기기 ID이거나 verified: false
    }
  } else if (event.deviceRegistered === true) {
    isConfirmedDevice = true;
  }

  return {
    timestamp,
    subject,
    isGet,
    count,
    unusualNetwork,
    isConfirmedDevice,
    isInvalidDevice,
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

function evaluateEvents(events) {
  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();
  let confirmedSubject = null;

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], i * 1000);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
    }
    if (input.isConfirmedDevice && !confirmedSubject) {
      confirmedSubject = input.subject;
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
    let invalidInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      windowReads += cur.count;
      if (cur.unusualNetwork) unusualInWindow += cur.count;
      if (cur.isConfirmedDevice) confirmedInWindow += cur.count;
      if (cur.isInvalidDevice) invalidInWindow += cur.count;

      while (
        list[lastInWindow].timestamp > 0
        && list[firstInWindow].timestamp > 0
        && list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS
      ) {
        const first = list[firstInWindow];
        windowReads -= first.count;
        if (first.unusualNetwork) unusualInWindow -= first.count;
        if (first.isConfirmedDevice) confirmedInWindow -= first.count;
        if (first.isInvalidDevice) invalidInWindow -= first.count;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건을 넘을 때만 검사 (정확히 120건은 제외)
      if (windowReads > BURST_LIMIT) {
        // 확인되지 않은 기기나 다른 기기 ID가 있으면 회수 제안 미생성 (계약 line 17)
        if (invalidInWindow === 0 && confirmedInWindow > 0) {
          // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
          // 120건 초과 조회와 명시적인 비정상 네트워크 신호가 결합된 경우
          if (unusualInWindow > 0 || hasUnusualSignal) {
            return revocationProposal('unusual_network_burst_read', subject);
          }

          // [2. 단순 다량 조회 규칙]
          // 구간 전체가 확인된 가상 기기 한 대로만 구성되고 비정상 네트워크 신호 없음
          if (confirmedInWindow === windowReads) {
            burstCandidate ??= subject;
          }
        }
      }
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}

export function detect(rawEvents) {
  let inputSource = rawEvents;
  if (typeof inputSource === 'string') {
    try { inputSource = JSON.parse(inputSource); } catch {}
  }

  // 배치(배열) 전달인 경우
  if (Array.isArray(inputSource)) {
    // 다건 배치인 경우 해당 배치를 독립적으로 평가하고 스트리밍 히스토리 리셋
    if (inputSource.length > 1) {
      streamingHistory.length = 0;
      return evaluateEvents(inputSource);
    }
    // 단건 배열인 경우 배치 평가 후 스트리밍 히스토리에도 누적
    const singleResult = evaluateEvents(inputSource);
    if (inputSource.length === 1 && inputSource[0]) {
      addStreamingEvent(inputSource[0]);
      if (singleResult.action === 'observe') {
        const streamResult = evaluateEvents(streamingHistory);
        if (streamResult.action !== 'observe') return streamResult;
      }
    }
    return singleResult;
  }

  // 객체 래핑 배열 전달인 경우 (events, alerts, data 등)
  if (inputSource !== null && typeof inputSource === 'object') {
    for (const key of ['events', 'alerts', 'data', 'requests', 'records', 'items', 'logs', 'entries', 'history']) {
      if (Array.isArray(inputSource[key])) {
        streamingHistory.length = 0;
        return evaluateEvents(inputSource[key]);
      }
    }

    // 단건 이벤트 객체가 직접 전달된 경우: 스트리밍 기록에 누적하고 평가
    addStreamingEvent(inputSource);
    return evaluateEvents(streamingHistory);
  }

  throw new TypeError('invalid_detection_events');
}

export default detect;