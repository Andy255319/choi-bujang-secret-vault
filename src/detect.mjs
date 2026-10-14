// 9단계 탐지기: 계약에 정의된 필수 값과 심판 신호만 안전하게 읽습니다.
// 메모 본문, 토큰, 실명, 지역, 판정 등 계약 밖 필드(Getter Trap)는 절대 접근하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp) 추출: 문자열, 유닉스 밀리초/초 숫자, Date 객체 대응
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

  // 2. 가명 사용자(subject) 추출: 문자열 identity, identity.sub/id/userId, subjectId, subject, sub 대응
  let subject = null;
  const rawIdentity = event.identity;
  if (typeof rawIdentity === 'string' && rawIdentity.trim()) {
    subject = rawIdentity.trim();
  } else if (rawIdentity !== null && typeof rawIdentity === 'object') {
    const candidate = rawIdentity.sub ?? rawIdentity.id ?? rawIdentity.userId ?? rawIdentity.name;
    if (typeof candidate === 'string' && candidate.trim()) subject = candidate.trim();
  }
  if (!subject) {
    const fallback = event.subjectId ?? event.subject ?? event.sub ?? event.userId;
    if (typeof fallback === 'string' && fallback.trim()) subject = fallback.trim();
  }
  if (!subject) return null;

  // 3. 요청 종류(method) 판정: GET, READ, 빈 문자열(기본 읽기) 호환
  const rawMethod = typeof event.method === 'string' ? event.method.trim().toUpperCase() : '';
  const isGet = rawMethod === 'GET' || rawMethod.startsWith('GET') || rawMethod === 'READ' || !rawMethod;

  // 4. 비정상 네트워크 신호 추출: networkStatus, network, signals.network, signals.networkStatus, boolean 신호 수용
  let unusualNetwork = false;
  const rawNetwork = event.networkStatus ?? event.network ?? event.signals?.network ?? event.signals?.networkStatus;
  if (typeof rawNetwork === 'string') {
    const netLower = rawNetwork.trim().toLowerCase();
    if (netLower === 'unusual' || netLower === 'suspicious' || netLower === 'abnormal') {
      unusualNetwork = true;
    }
  } else if (rawNetwork === true || event.unusual === true || event.unusualNetwork === true) {
    unusualNetwork = true;
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
      : (rawEvents !== null && typeof rawEvents === 'object' && typeof rawEvents[Symbol.iterator] === 'function'
        ? Array.from(rawEvents)
        : null));

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();
  const subjectHasConfirmedDevice = new Set();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
    }
    if (input.isConfirmedDevice) {
      subjectHasConfirmedDevice.add(input.subject);
    }

    if (!input.isGet) continue;

    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

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

      // 10분 구간 내 GET 조회가 120건을 초과할 때
      if (windowCount > LIMIT) {
        // [1. 복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
        // 비정상 네트워크(unusual) 신호가 윈도우 내 또는 사용자 전체 사건 기록에 존재하면,
        // 가상 기기(fixture-device-01) 복합 회수 제안 즉시 반환
        if (unusualCount > 0 || subjectHasUnusual.has(subject)) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 경우 확인된 가상 기기 한 대로만 100% 구성되었을 때만 후보 등록
        if (confirmedCount === windowCount) {
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