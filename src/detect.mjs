// 9단계 로컬 연습용 탐지기입니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약에 정의된 가상 사건 필드만 읽습니다. 민감 필드는 읽거나 복사하지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = typeof event.method === 'string' ? event.method.trim().toUpperCase() : '';
  const subject = event.identity?.sub ?? event.subject ?? event.subjectId;

  // 비정상 네트워크 신호 식별 (docs/DETECT_EVENTS.md 기준)
  const unusualNetwork = event.networkStatus === 'unusual'
    || event.network === 'unusual'
    || event.signals?.network === 'unusual';

  // 확인된 단일 가상 기기 판별
  const virtualDevice = event.virtualDevice;
  const confirmedDeviceId = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID
    ? VIRTUAL_DEVICE_ID
    : null;

  if (typeof subject !== 'string' || !subject || at === undefined || at === null) return null;

  return { at, method, subject, unusualNetwork, confirmedDeviceId };
}

function parseTimestamp(at) {
  if (typeof at === 'number') return at;
  if (at instanceof Date) return at.getTime();
  return Date.parse(at);
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

    const timestamp = parseTimestamp(input.at);
    if (!Number.isFinite(timestamp)) continue;

    const reads = readsBySubject.get(input.subject) ?? [];
    reads.push({
      timestamp,
      unusualNetwork: input.unusualNetwork,
      confirmedDeviceId: input.confirmedDeviceId,
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
      if (reads[lastInWindow].confirmedDeviceId === VIRTUAL_DEVICE_ID) confirmedCount += 1;

      while (reads[lastInWindow].timestamp - reads[firstInWindow].timestamp > WINDOW_MS) {
        if (reads[firstInWindow].unusualNetwork) unusualCount -= 1;
        if (reads[firstInWindow].confirmedDeviceId === VIRTUAL_DEVICE_ID) confirmedCount -= 1;
        firstInWindow += 1;
      }

      const windowCount = lastInWindow - firstInWindow + 1;

      // 10분 구간 내 120건 초과 조회 발생 시
      if (windowCount > LIMIT) {
        // 복합 의심 사건: 확인된 기기 신호가 포함되어 있고 비정상 네트워크 신호가 함께 존재할 때
        // 도플갱어 요청이 섞여 있어도 즉시 복합 회수 제안을 반환합니다.
        if (confirmedCount > 0 && unusualCount > 0) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // 기존 단순 다량 조회: 전건이 확인된 기기 하나로만 구성된 경우
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