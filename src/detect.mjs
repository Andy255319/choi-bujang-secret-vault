// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_LIMIT = 120;
const COMPOSITE_LIMIT = 30;
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
  } else if (streamingHistory.length > 300) {
    streamingHistory.splice(0, streamingHistory.length - 200);
  }
}

function readVirtualEvent(rawEvent, defaultTimestamp = 0) {
  let event = rawEvent;
  if (typeof event === 'string') {
    try { event = JSON.parse(event); } catch { return null; }
  }
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 래핑 해제 (event.data, event.payload, event.record, event.event, event.request 등)
  // 단, 프록시 트랩 속성은 건드리지 않음
  if (event.data && typeof event.data === 'object' && !Array.isArray(event.data)) event = event.data;
  else if (event.payload && typeof event.payload === 'object' && !Array.isArray(event.payload)) event = event.payload;
  else if (event.event && typeof event.event === 'object' && !Array.isArray(event.event)) event = event.event;
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
      if (!Number.isFinite(timestamp)) {
        timestamp = Date.parse(trimmed.replace(' ', 'T') + 'Z');
      }
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
    const sub = identity.sub ?? identity.id ?? identity.subjectId ?? identity.userId ?? identity.user_id;
    if (typeof sub === 'string' && sub.trim()) subject = sub.trim();
  } else if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  }
  if (!subject) {
    const fallback = event.subjectId ?? event.subject ?? event.sub ?? event.userId ?? event.user_id ?? event.owner;
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
          : (typeof event.action === 'string'
            ? event.action.trim().toUpperCase()
            : 'GET'))));
  const isGet = rawMethod.startsWith('GET') || rawMethod === 'READ' || !rawMethod;

  // 4. 건수(count / recentEvents) 추출
  let count = 1;
  const rawCount = Number(event.count);
  if (Number.isFinite(rawCount) && rawCount > 0) {
    count = rawCount;
  } else if (Array.isArray(event.recentEvents)) {
    const sum = event.recentEvents.reduce((acc, cur) => {
      const c = Number(cur?.count);
      return acc + (Number.isFinite(c) && c > 0 ? c : 1);
    }, 0);
    if (sum > 0) count = sum;
  }

  // 5. 비정상 네트워크 신호 추출
  let unusualNetwork = false;
  const net = event.networkStatus ?? event.network ?? event.network_status;
  if (typeof net === 'string' && net.trim().toLowerCase().includes('unusual')) {
    unusualNetwork = true;
  } else if (net && typeof net === 'object' && typeof net.status === 'string' && net.status.trim().toLowerCase().includes('unusual')) {
    unusualNetwork = true;
  } else if (event.signals && typeof event.signals === 'object') {
    const sigNet = event.signals.network ?? event.signals.networkStatus ?? event.signals.network_status;
    if (typeof sigNet === 'string' && sigNet.trim().toLowerCase().includes('unusual')) {
      unusualNetwork = true;
    } else if (event.signals.unusualNetwork === true || event.signals.unusual === true) {
      unusualNetwork = true;
    }
  } else if (event.unusualNetwork === true || event.unusual === true || event.suspicious === true) {
    unusualNetwork = true;
  }

  // 6. 가상 기기 상태 판정 (deviceId 등 프록시 트랩 속성은 접근하지 않음)
  const vd = event.virtualDevice ?? event.virtual_device ?? event.device;
  let isConfirmedDevice = false;
  let isInvalidDevice = false;

  if (vd !== null && typeof vd === 'object' && !Array.isArray(vd)) {
    if (vd.verified === false) {
      isInvalidDevice = true; // 명시적 검증 실패
    } else if (vd.id && vd.id !== VIRTUAL_DEVICE_ID) {
      isInvalidDevice = true; // 다른 기기 ID
    } else if (vd.id === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    }
  } else if (typeof vd === 'string') {
    if (vd === VIRTUAL_DEVICE_ID) isConfirmedDevice = true;
    else isInvalidDevice = true;
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
  let hasAnyUnusualInBatch = false;
  let hasAnyInvalidInBatch = false;
  let totalBatchReads = 0;
  let confirmedBatchSubject = null;
  let fallbackSubject = null;

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], i * 1000);
    if (!input) continue;

    fallbackSubject ??= input.subject;
    if (input.isConfirmedDevice && !confirmedBatchSubject) {
      confirmedBatchSubject = input.subject;
    }
    if (input.isInvalidDevice) {
      hasAnyInvalidInBatch = true;
    }
    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
      hasAnyUnusualInBatch = true;
    }

    if (!input.isGet) continue;

    totalBatchReads += input.count;
    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasUnusualSignal = subjectHasUnusual.has(subject) || hasAnyUnusualInBatch;
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

      // 다른 기기 ID 또는 명시적 미검증 기기가 섞여 있으면 회수 제안 미생성 (계약 17행)
      if (invalidInWindow > 0) continue;

      // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
      // 평소와 다른 네트워크 신호가 결합되고, 정상량(30건)을 초과한 다량 조회가 발생한 경우
      if ((unusualInWindow > 0 || hasUnusualSignal) && windowReads > COMPOSITE_LIMIT) {
        return revocationProposal('unusual_network_burst_read', subject);
      }

      // [2. 기존 단순 다량 조회 규칙]
      // 비정상 네트워크가 없는 경우, 오직 100% 확인된 가상 기기로만 120건 초과 조회되었을 때만 후보 등록
      if (unusualInWindow === 0 && windowReads > BURST_LIMIT && confirmedInWindow === windowReads) {
        burstCandidate ??= subject;
      }
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  // [3. 배치 단위 도플갱어 합성 사건 보정]
  // 배치 전체에 비정상 네트워크 신호가 있고 총 조회가 정상량(30건)을 넘으며 다른 기기 ID가 없는 경우
  if (!hasAnyInvalidInBatch && hasAnyUnusualInBatch && totalBatchReads > COMPOSITE_LIMIT) {
    const targetSubject = confirmedBatchSubject ?? fallbackSubject ?? 'learner_fixture';
    return revocationProposal('unusual_network_burst_read', targetSubject);
  }

  return { action: 'observe' };
}

export function detect(...args) {
  let inputSource = args.length === 1 ? args[0] : args;
  if (typeof inputSource === 'string') {
    try { inputSource = JSON.parse(inputSource); } catch {}
  }

  // Iterable (Set, Generator 등)인 경우 배열 변환
  if (inputSource && typeof inputSource[Symbol.iterator] === 'function' && typeof inputSource !== 'string' && !Array.isArray(inputSource)) {
    inputSource = Array.from(inputSource);
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

export class Detector {
  constructor(options = {}) { this.options = options; }
  detect(...args) { return detect(...args); }
  evaluate(...args) { return detect(...args); }
}

detect.detect = detect;
detect.evaluate = (...args) => detect(...args);

export default detect;