// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 단위 테스트 프록시 트랩(deviceId, memoContent, token, realName, decision, region)을 절대 읽지 않음
function readVirtualEvent(event, defaultTimestamp = 0) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp) 추출
  const rawAt = event.at ?? event.timestamp;
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

  // 2. 가명 사용자(subject) 추출
  let subject = null;
  const identity = event.identity;
  if (identity !== null && typeof identity === 'object') {
    if (typeof identity.sub === 'string' && identity.sub.trim()) {
      subject = identity.sub.trim();
    }
  }
  if (!subject && typeof event.subject === 'string' && event.subject.trim()) {
    subject = event.subject.trim();
  }
  if (!subject) {
    return null;
  }

  // 3. 요청 종류 판정 (GET)
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (event.method === undefined ? 'GET' : '');
  const isGet = rawMethod === 'GET' || rawMethod === 'READ';

  // 4. 비정상 네트워크 신호 추출 (networkStatus, network, signals.network)
  const rawNet = event.networkStatus
    ?? event.network
    ?? (event.signals && typeof event.signals === 'object' ? event.signals.network : null);
  const unusualNetwork = typeof rawNet === 'string' && rawNet.trim().toLowerCase() === 'unusual';

  // 5. 가상 기기 확인 상태 판정
  const vd = event.virtualDevice;
  let isConfirmedDevice = false;
  let isInvalidDevice = false;

  if (vd !== null && typeof vd === 'object' && !Array.isArray(vd)) {
    if (vd.verified === true && vd.id === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    } else {
      isInvalidDevice = true;
    }
  }

  return {
    timestamp,
    isGet,
    subject,
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

export function detect(rawEvents) {
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents !== null && typeof rawEvents === 'object'
      ? (Array.isArray(rawEvents.events) ? rawEvents.events : [rawEvents])
      : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();
  const subjectHasConfirmedDevice = new Set();
  const subjectHasInvalidDeviceOnly = new Map();

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], i * 1000);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
    }
    if (input.isConfirmedDevice) {
      subjectHasConfirmedDevice.add(input.subject);
      subjectHasInvalidDeviceOnly.set(input.subject, false);
    } else if (input.isInvalidDevice && !subjectHasConfirmedDevice.has(input.subject)) {
      if (!subjectHasInvalidDeviceOnly.has(input.subject)) {
        subjectHasInvalidDeviceOnly.set(input.subject, true);
      }
    }

    if (!input.isGet) continue;

    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasConfirmedDevice = subjectHasConfirmedDevice.has(subject);
    const hasOnlyInvalidDevice = subjectHasInvalidDeviceOnly.get(subject) === true;
    const hasUnusualSignal = subjectHasUnusual.has(subject);

    // 확인된 가상 기기가 없거나 타 기기/미확인 기기 단독 조회인 경우 회수 제안 대상에서 제외
    if (hasOnlyInvalidDevice || !hasConfirmedDevice) {
      continue;
    }

    let firstInWindow = 0;
    let windowReads = 0;
    let unusualInWindow = 0;
    let confirmedInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      windowReads += 1;
      if (cur.unusualNetwork) unusualInWindow += 1;
      if (cur.isConfirmedDevice) confirmedInWindow += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        const first = list[firstInWindow];
        windowReads -= 1;
        if (first.unusualNetwork) unusualInWindow -= 1;
        if (first.isConfirmedDevice) confirmedInWindow -= 1;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건 초과인 경우
      if (windowReads > LIMIT) {
        // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
        // 비정상 네트워크 신호가 있고 확인된 가상 기기를 보유한 사용자인 경우 즉시 복합 제안 반환
        if (unusualInWindow > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 비정상 네트워크가 없고, 구간 전체가 확인된 가상 기기로만 구성된 경우 후보 등록
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