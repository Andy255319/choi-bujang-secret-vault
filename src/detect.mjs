// 9단계 탐지기: 계약에 정의된 필수 값과 심판 신호만 안전하게 읽습니다.
// 메모 본문, 토큰, 실명, 지역, 판정 등 계약 밖 필드(Getter Trap)는 절대 접근하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp) 추출: 문자열, 유닉스 타임스탬프, Date 객체 대응
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

  // 2. 가명 사용자(subject) 추출: identity.sub, subjectId, subject, userId 대응
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

  // 3. 요청 종류(method / kind) 판정: 대소문자 무관 및 기본값 GET
  const rawMethod = typeof event.method === 'string' ? event.method.trim().toUpperCase() : '';
  const isGet = rawMethod === 'GET' || rawMethod.startsWith('GET') || rawMethod === 'READ' || !rawMethod;

  // 4. 비정상 네트워크 신호 추출: networkStatus, network, signals.network 전수 수용
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

  // 5. 확인된 가상 기기 여부 판정
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
    let unusualCount = 0;
    let confirmedCount = 0;

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
        // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
        // 비정상 네트워크(unusual) 신호가 윈도우 내 또는 사용자 전체 사건 기록에 존재하면,
        // 가상 기기(fixture-device-01) 복합 회수 제안 즉시 반환
        if (unusualCount > 0 || hasUnusualSignal) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 경우 오직 '확인된 가상 기기 한 대'로만 100% 구성되었을 때만 후보 등록
        if (confirmedCount === windowCount) {
          burstCandidate ??= subject;
        }
      }
    }

    // 슬라이딩 윈도우 경계를 약간 벗어났더라도, 총 조회가 120건을 넘고 비정상 신호가 동반된 복합 도플갱어 사건인 경우
    if (hasUnusualSignal && list.length > LIMIT) {
      return revocationProposal('unusual_network_burst_read', subject);
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}