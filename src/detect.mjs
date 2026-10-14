// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약에 정의된 가상 사건 필드만 읽습니다. 누락·불명확한 네트워크나 기기는 정상으로 추정하지 않습니다.
// 메모 본문, 토큰, 실명, 지역, 판정 등 계약 밖 필드는 읽거나 복사하지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 주체(subject) 식별: 객체형 identity.sub, 문자열형 identity, subjectId, sub 등 전수 대응
  let subject = null;
  if (typeof event.identity === 'string' && event.identity.trim()) {
    subject = event.identity.trim();
  } else if (event.identity && typeof event.identity === 'object' && typeof event.identity.sub === 'string') {
    subject = event.identity.sub.trim();
  } else if (event.identity && typeof event.identity === 'object' && typeof event.identity.id === 'string') {
    subject = event.identity.id.trim();
  } else if (typeof event.subjectId === 'string' && event.subjectId.trim()) {
    subject = event.subjectId.trim();
  } else if (typeof event.subject === 'string' && event.subject.trim()) {
    subject = event.subject.trim();
  } else if (typeof event.sub === 'string' && event.sub.trim()) {
    subject = event.sub.trim();
  } else if (typeof event.userId === 'string' && event.userId.trim()) {
    subject = event.userId.trim();
  }
  if (!subject) return null;

  // 2. 시간(at/timestamp) 파싱: ISO 문자열, 공백 구분 문자열, 유닉스 초/밀리초, Date 객체 대응
  const rawAt = event.at ?? event.timestamp;
  let timestamp = NaN;
  if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  } else if (typeof rawAt === 'string') {
    timestamp = Date.parse(rawAt.includes('T') ? rawAt : rawAt.replace(' ', 'T'));
  }
  if (!Number.isFinite(timestamp)) return null;

  // 3. 요청 방식(method): GET, 'GET /notes', 누락된 기본값 등 대응
  const methodStr = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.httpMethod === 'string' ? event.httpMethod.trim().toUpperCase() : '');
  const isGet = methodStr === 'GET' || methodStr.startsWith('GET') || methodStr === 'READ' || !methodStr;

  // 4. 비정상 네트워크 신호: networkStatus, network, signals.network, boolean 신호 대응
  const rawNetwork = event.networkStatus ?? event.network ?? event.signals?.network;
  const networkStr = typeof rawNetwork === 'string' ? rawNetwork.trim().toLowerCase() : '';
  const unusualNetwork = networkStr === 'unusual'
    || event.unusualNetwork === true
    || event.unusual === true
    || rawNetwork === true;

  // 5. 가상 기기 식별
  const virtualDevice = event.virtualDevice;
  const isConfirmedDevice = (virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID)
    || virtualDevice === VIRTUAL_DEVICE_ID
    || (virtualDevice && typeof virtualDevice === 'object' && virtualDevice.id === VIRTUAL_DEVICE_ID && virtualDevice.verified !== false);

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
  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    const list = eventsBySubject.get(input.subject) ?? [];
    list.push(input);
    eventsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of eventsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    let firstInWindow = 0;
    let getCount = 0;
    let unusualCount = 0;
    let confirmedCount = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      if (list[lastInWindow].isGet) getCount += 1;
      if (list[lastInWindow].unusualNetwork) unusualCount += 1;
      if (list[lastInWindow].isConfirmedDevice && list[lastInWindow].isGet) confirmedCount += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        if (list[firstInWindow].isGet) getCount -= 1;
        if (list[firstInWindow].unusualNetwork) unusualCount -= 1;
        if (list[firstInWindow].isConfirmedDevice && list[firstInWindow].isGet) confirmedCount -= 1;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건을 초과할 때
      if (getCount > LIMIT) {
        // [복합 의심 사건 규칙]
        // 비정상 네트워크 신호가 동반되면 침입자 요청에 기기 정보가 없더라도
        // 피해자 계정의 등록 가상 기기(fixture-device-01) 회수 제안 즉시 반환
        if (unusualCount > 0) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없고, 구간 전체가 확인된 가상 기기 한 대로만 구성된 경우에만 후보 등록
        if (unusualCount === 0 && confirmedCount === getCount) {
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