// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약에 정의된 가상 사건 필드만 읽습니다. 누락·불명확한 네트워크나 기기는 정상으로 추정하지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = typeof event.method === 'string' ? event.method.trim().toUpperCase() : '';
  const subject = event.identity?.sub;
  const unusualNetwork = event.networkStatus === 'unusual';
  const virtualDevice = event.virtualDevice;

  const isConfirmedDevice = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID;

  if (typeof subject !== 'string' || !subject) return null;

  let timestamp = NaN;
  if (typeof at === 'number') {
    timestamp = at;
  } else if (at instanceof Date) {
    timestamp = at.getTime();
  } else if (typeof at === 'string') {
    timestamp = Date.parse(at);
  }
  if (!Number.isFinite(timestamp)) return null;

  return { timestamp, method, subject, unusualNetwork, isConfirmedDevice };
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
  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input || input.method !== 'GET') continue;

    const reads = readsBySubject.get(input.subject) ?? [];
    reads.push({
      timestamp: input.timestamp,
      unusualNetwork: input.unusualNetwork,
      isConfirmedDevice: input.isConfirmedDevice,
    });
    readsBySubject.set(input.subject, reads);
  }

  let complexCandidate = null;
  let burstCandidate = null;

  for (const [subject, reads] of readsBySubject) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    let firstInWindow = 0;
    let unusualCount = 0;
    let confirmedCount = 0;

    for (let lastInWindow = 0; lastInWindow < reads.length; lastInWindow += 1) {
      if (reads[lastInWindow].unusualNetwork) unusualCount += 1;
      if (reads[lastInWindow].isConfirmedDevice) confirmedCount += 1;

      while (reads[lastInWindow].timestamp - reads[firstInWindow].timestamp > WINDOW_MS) {
        if (reads[firstInWindow].unusualNetwork) unusualCount -= 1;
        if (reads[firstInWindow].isConfirmedDevice) confirmedCount -= 1;
        firstInWindow += 1;
      }

      const windowCount = lastInWindow - firstInWindow + 1;

      // 10분 구간 내 조회가 120건을 초과할 때
      if (windowCount > LIMIT) {
        // 1. 복합 의심 사건: 비정상 네트워크가 존재하고, 확인된 대상 기기가 구간 내에 존재하는 경우
        if (unusualCount > 0 && confirmedCount > 0) {
          complexCandidate ??= subject;
        }
        // 2. 단순 다량 조회: 비정상 네트워크가 없고, 구간 전체가 확인된 대상 기기만으로 구성된 경우
        else if (unusualCount === 0 && confirmedCount === windowCount) {
          burstCandidate ??= subject;
        }
      }
    }
  }

  // 복합 의심 사건(unusual_network_burst_read)을 단순 다량 조회보다 무조건 우선 반환
  if (complexCandidate) {
    return revocationProposal('unusual_network_burst_read', complexCandidate);
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}