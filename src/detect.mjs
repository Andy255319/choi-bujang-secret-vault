// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 민감 필드(deviceId, memoContent, token, realName, decision, region)를 건드리지 않고
// 계약에 정의된 필수 값과 심판 신호만 안전하게 읽습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp) 추출: 문자열, 숫자(초/밀리초), Date 객체 대응
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
  } else if (typeof event.userId === 'string' && event.userId.trim()) {
    subject = event.userId.trim();
  }
  if (!subject) return null;

  // 3. 요청 종류(method / kind) 추출: 대소문자 무관 및 기본값 GET
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.kind === 'string' ? event.kind.trim().toUpperCase() : 'GET');
  const isGet = rawMethod === 'GET' || rawMethod.startsWith('GET') || rawMethod === 'READ';

  // 4. 비정상 네트워크 신호 추출: networkStatus, signals.network, network 대응
  const rawNetwork = event.networkStatus
    ?? event.network
    ?? (event.signals && typeof event.signals === 'object' ? event.signals.network : null);
  const unusualNetwork = typeof rawNetwork === 'string' && rawNetwork.trim().toLowerCase() === 'unusual';

  // 5. 가상 기기 확인 상태
  const virtualDevice = event.virtualDevice;
  let isConfirmedDevice = false;
  let isOtherDevice = false;

  if (virtualDevice !== null && typeof virtualDevice === 'object' && !Array.isArray(virtualDevice)) {
    if (virtualDevice.verified === true && virtualDevice.id === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    } else {
      isOtherDevice = true;
    }
  } else if (typeof virtualDevice === 'string' && virtualDevice === VIRTUAL_DEVICE_ID) {
    isConfirmedDevice = true;
  }

  return {
    timestamp,
    isGet,
    subject,
    unusualNetwork,
    isConfirmedDevice,
    isOtherDevice,
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

  const readsBySubject = new Map();
  const subjectHasConfirmedDevice = new Set();
  const subjectHasOtherDeviceOnly = new Map();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input || !input.isGet) continue;

    if (input.isConfirmedDevice) {
      subjectHasConfirmedDevice.add(input.subject);
      subjectHasOtherDeviceOnly.set(input.subject, false);
    } else if (input.isOtherDevice && !subjectHasConfirmedDevice.has(input.subject)) {
      if (!subjectHasOtherDeviceOnly.has(input.subject)) {
        subjectHasOtherDeviceOnly.set(input.subject, true);
      }
    }

    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasConfirmedSomewhere = subjectHasConfirmedDevice.has(subject);
    const hasOnlyOtherDevice = subjectHasOtherDeviceOnly.get(subject) === true;

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
        // [1. 복합 의심 사건 규칙: 합성 도플갱어 접속 사건 대응]
        // 120건 초과 구간에 비정상 네트워크(unusual) 신호가 포함되어 있고,
        // 사용자에게 확인된 가상 기기가 존재하거나 명시적 타 기기 단독 조회가 아닌 경우 복합 제안 반환
        if (unusualCount > 0) {
          if (confirmedCount > 0 || hasConfirmedSomewhere || !hasOnlyOtherDevice) {
            return revocationProposal('unusual_network_burst_read', subject);
          }
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 경우 오직 '확인된 가상 기기 한 대'로만 100% 구성되었을 때만 후보 등록
        if (unusualCount === 0 && confirmedCount === windowCount) {
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