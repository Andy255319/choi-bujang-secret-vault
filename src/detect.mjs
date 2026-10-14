// 9단계 탐지기: 계약에 정의된 5개 필드만 안전하게 읽습니다.
// 메모 본문, 토큰, 실명, 지역, 판정 등 계약 밖 필드는 절대 접근하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = event.method;
  const identity = event.identity;
  const subject = identity !== null && typeof identity === 'object' ? identity.sub : null;
  const networkStatus = event.networkStatus;
  const virtualDevice = event.virtualDevice;

  if (typeof subject !== 'string' || !subject || typeof at !== 'string') return null;

  const timestamp = Date.parse(at);
  if (!Number.isFinite(timestamp)) return null;

  const isConfirmedDevice = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID;

  return {
    timestamp,
    isGet: method === 'GET',
    subject,
    unusualNetwork: networkStatus === 'unusual',
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
        // 비정상 네트워크(unusual) 신호가 윈도우 안 또는 해당 주체의 사건 기록에 존재하면,
        // 도플갱어 요청에 기기 정보가 없더라도 계정 소유자의 가상 기기(fixture-device-01) 회수 제안 즉시 반환
        if (unusualCount > 0 || subjectHasUnusual.has(subject)) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 경우 오직 '확인된 가상 기기 한 대'로만 100% 구성되었을 때만 후보 등록
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