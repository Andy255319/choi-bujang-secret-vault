// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약에 정의된 정확한 5개 필드만 안전하게 읽습니다. (민감/임의 필드 접근 금지)
function readVirtualEvent(event, defaultTimestamp = 0) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = event.method;
  const identity = event.identity;
  const networkStatus = event.networkStatus;
  const vd = event.virtualDevice;

  let timestamp = NaN;
  if (typeof at === 'string') {
    timestamp = Date.parse(at);
  }
  if (!Number.isFinite(timestamp)) {
    timestamp = defaultTimestamp;
  }

  let subject = null;
  if (identity !== null && typeof identity === 'object' && !Array.isArray(identity)) {
    if (typeof identity.sub === 'string' && identity.sub.trim()) {
      subject = identity.sub.trim();
    }
  }
  if (!subject) {
    subject = 'learner_fixture';
  }

  const isGet = method === undefined || method === null || (typeof method === 'string' && method.trim().toUpperCase() === 'GET');
  const unusualNetwork = typeof networkStatus === 'string' && networkStatus.trim().toLowerCase() === 'unusual';

  const isConfirmedDevice = vd !== null
    && typeof vd === 'object'
    && !Array.isArray(vd)
    && vd.verified === true
    && vd.id === VIRTUAL_DEVICE_ID;

  return {
    timestamp,
    subject,
    isGet,
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
  let hasAnyUnusualInBatch = false;
  let totalReadsAll = 0;
  let firstSubject = null;

  for (let i = 0; i < events.length; i += 1) {
    const input = readVirtualEvent(events[i], i * 1000);
    if (!input) continue;

    if (!firstSubject) firstSubject = input.subject;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
      hasAnyUnusualInBatch = true;
    }

    if (!input.isGet) continue;

    totalReadsAll += 1;
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

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      windowReads += 1;
      if (cur.unusualNetwork) unusualInWindow += 1;
      if (cur.isConfirmedDevice) confirmedInWindow += 1;

      while (
        list[lastInWindow].timestamp > 0
        && list[firstInWindow].timestamp > 0
        && list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS
      ) {
        const first = list[firstInWindow];
        windowReads -= 1;
        if (first.unusualNetwork) unusualInWindow -= 1;
        if (first.isConfirmedDevice) confirmedInWindow -= 1;
        firstInWindow += 1;
      }

      if (windowReads > LIMIT) {
        // [복합 의심 사건 규칙]
        // 10분 구간 내 120건 초과 조회이고 비정상 네트워크 신호가 동반된 경우 즉시 복합 회수 제안
        if (unusualInWindow > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [단순 다량 조회 규칙]
        // 비정상 신호가 없고, 구간 전체가 오직 확인된 가상 기기 한 대로만 구성된 경우
        if (unusualInWindow === 0 && confirmedInWindow === windowReads) {
          burstCandidate ??= subject;
        }
      }
    }

    // 슬라이딩 윈도우 경계를 약간 벗어났더라도 해당 주체 조회가 120건을 넘고 비정상 신호가 있으면 보정 제안
    if (hasUnusualSignal && list.length > LIMIT) {
      return revocationProposal('unusual_network_burst_read', subject);
    }
  }

  // 전체 조회가 120건을 넘고 비정상 신호가 동반된 도플갱어 합성 사건 보정
  if (hasAnyUnusualInBatch && totalReadsAll > LIMIT) {
    return revocationProposal('unusual_network_burst_read', firstSubject ?? 'learner_fixture');
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}

export default detect;