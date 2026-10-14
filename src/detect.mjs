// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 민감 필드(deviceId, memoContent, token, realName, decision, region)를 건드리지 않고
// 계약에 정의된 필수 값과 심판 신호를 안전하게 읽습니다.
function readVirtualEvent(event) {
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
  if (!Number.isFinite(timestamp)) return null;

  // 2. 가명 사용자(subject) 추출
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

  // 3. 요청 종류(method / kind) 추출 (기본값 GET)
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.kind === 'string' ? event.kind.trim().toUpperCase() : 'GET');
  const isGet = rawMethod === 'GET' || rawMethod.startsWith('GET') || rawMethod === 'READ';

  // 4. 비정상 네트워크 신호 추출
  const rawNetwork = event.networkStatus
    ?? event.network
    ?? (event.signals && typeof event.signals === 'object' ? event.signals.network : null);
  const unusualNetwork = typeof rawNetwork === 'string' && rawNetwork.trim().toLowerCase() === 'unusual';

  // 5. 가상 기기 확인 상태
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

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const eventsBySubject = new Map();
  const subjectHasUnusualOverall = new Set();

  // 모든 사건을 수집하여 비정상 네트워크 신호가 비-GET 사건에 있더라도 기록
  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusualOverall.add(input.subject);
    }

    const list = eventsBySubject.get(input.subject) ?? [];
    list.push(input);
    eventsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of eventsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasUnusualSignal = subjectHasUnusualOverall.has(subject);
    let firstInWindow = 0;
    let getCountInWindow = 0;
    let unusualInWindow = 0;
    let confirmedInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      if (cur.isGet) getCountInWindow += 1;
      if (cur.unusualNetwork) unusualInWindow += 1;
      if (cur.isConfirmedDevice && cur.isGet) confirmedInWindow += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        const first = list[firstInWindow];
        if (first.isGet) getCountInWindow -= 1;
        if (first.unusualNetwork) unusualInWindow -= 1;
        if (first.isConfirmedDevice && first.isGet) confirmedInWindow -= 1;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건을 초과할 때
      if (getCountInWindow > LIMIT) {
        // [1. 복합 의심 사건 규칙: 합성 도플갱어 접속 사건 대응]
        // 10분 윈도우 내 또는 해당 주체의 사건 기록에 비정상 네트워크 신호가 동반된 경우 복합 회수 제안
        if (unusualInWindow > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 경우 오직 '확인된 가상 기기 한 대'로만 100% 구성되었을 때만 후보 등록
        if (confirmedInWindow === getCountInWindow) {
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