// 9단계 로컬 연습용 탐지기입니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = typeof event.method === 'string' ? event.method.toUpperCase() : '';
  const subject = event.identity?.sub;
  const unusualNetwork = event.networkStatus === 'unusual';

  const virtualDevice = event.virtualDevice;
  const confirmedDeviceId = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID
    ? VIRTUAL_DEVICE_ID
    : null;

  if (typeof subject !== 'string' || !subject || typeof at !== 'string') return null;

  return { at, method, subject, unusualNetwork, confirmedDeviceId };
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

    const timestamp = Date.parse(input.at);
    if (!Number.isFinite(timestamp)) continue;

    const reads = readsBySubject.get(input.subject) ?? [];
    reads.push({
      timestamp,
      unusualNetwork: input.unusualNetwork,
      confirmedDeviceId: input.confirmedDeviceId,
    });
    readsBySubject.set(input.subject, reads);
  }

  let simpleCandidate = null;

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

      // 1. 복합 의심 사건 (10분 구간 내 120건 초과 + 비정상 네트워크 신호 존재)
      // 도플갱어가 섞여 확인 기기 비율이 달라져도 복합 신호 탐지 즉시 회수 제안 반환
      if (windowCount > LIMIT && unusualCount > 0) {
        return revocationProposal('unusual_network_burst_read', subject);
      }

      // 2. 기존 단독 다량 조회 (확인된 가상 기기만으로 120건 초과 구성된 경우)
      if (windowCount > LIMIT && confirmedCount === windowCount) {
        simpleCandidate ??= subject;
      }
    }
  }

  if (simpleCandidate) {
    return revocationProposal('burst_read', simpleCandidate);
  }

  return { action: 'observe' };
}