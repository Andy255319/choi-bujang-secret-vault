// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약에 정의된 값만 읽습니다. 누락·불명확한 네트워크나 기기는 정상으로 추정하지 않습니다.
// 메모 본문, 토큰, 실명, 지역 등 계약 밖 필드는 복사·저장하지 않습니다.
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

      // 10분 구간 내 조회가 120건을 초과하고 확인된 대상 가상 기기가 존재하는 경우
      if (windowCount > LIMIT && confirmedCount > 0) {
        // [복합 의심 규칙]: 비정상 네트워크 신호가 동반되면 즉시 최우선 반환
        if (unusualCount > 0) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [기존 단순 다량 조회]: 전건이 확인된 가상 기기이고 비정상 네트워크가 없는 경우
        if (confirmedCount === windowCount && unusualCount === 0) {
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