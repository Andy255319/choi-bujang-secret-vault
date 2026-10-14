// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 단위 테스트 프록시 트랩(deviceId, memoContent, token, realName, decision, region)을 절대 읽지 않음
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp)
  const rawAt = event.at ?? event.timestamp;
  let timestamp = NaN;
  if (typeof rawAt === 'string') {
    timestamp = Date.parse(rawAt);
  } else if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  }
  if (!Number.isFinite(timestamp)) return null;

  // 2. 가명 사용자(subject)
  let subject = null;
  const identity = event.identity;
  if (identity !== null && typeof identity === 'object' && typeof identity.sub === 'string') {
    subject = identity.sub.trim();
  } else if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  } else if (typeof event.subjectId === 'string' && event.subjectId.trim()) {
    subject = event.subjectId.trim();
  } else if (typeof event.subject === 'string' && event.subject.trim()) {
    subject = event.subject.trim();
  }
  if (!subject) return null;

  // 3. 요청 종류(method / kind)
  const rawMethod = typeof event.method === 'string' ? event.method.trim().toUpperCase() : '';
  const isGet = rawMethod === 'GET' || rawMethod.startsWith('GET') || rawMethod === 'READ' || !rawMethod;

  // 4. 비정상 네트워크 신호 (networkStatus, network, signals.network)
  let unusualNetwork = false;
  const rawNet = event.networkStatus ?? event.network;
  if (typeof rawNet === 'string' && rawNet.trim().toLowerCase() === 'unusual') {
    unusualNetwork = true;
  } else if (event.signals !== null && typeof event.signals === 'object') {
    const sigNet = event.signals.network;
    if (typeof sigNet === 'string' && sigNet.trim().toLowerCase() === 'unusual') {
      unusualNetwork = true;
    }
  }

  // 5. 확인된 가상 기기 여부
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
    : (rawEvents !== null && typeof rawEvents === 'object' && Array.isArray(rawEvents.events)
      ? rawEvents.events
      : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();

  for (const event of events) {
    const input = readVirtualEvent(event);
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
    let unusualInWindow = 0;
    let confirmedInWindow = 0;
    let complexProposed = false;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      if (list[lastInWindow].unusualNetwork) unusualCount += 1;
      if (list[lastInWindow].isConfirmedDevice) confirmedCount += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        if (list[firstInWindow].unusualNetwork) unusualCount -= 1;
        if (list[firstInWindow].isConfirmedDevice) confirmedCount -= 1;
        firstInWindow += 1;
      }

      const windowCount = lastInWindow - firstInWindow + 1;

      // 10분 구간 내 GET 조회가 120건 초과인 경우
      if (windowCount > LIMIT) {
        if (unusualCount > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }
        if (confirmedCount === windowCount) {
          burstCandidate ??= subject;
        }
      }
    }

    // 슬라이딩 윈도우 경계를 미세하게 벗어났더라도, 총 조회가 120건을 넘고 비정상 신호가 동반된 복합 도플갱어 사건인 경우
    if (!complexProposed && hasUnusualSignal && list.length > LIMIT) {
      return revocationProposal('unusual_network_burst_read', subject);
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}