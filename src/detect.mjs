// 9단계 로컬 연습용 탐지기입니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = typeof event.method === 'string' ? event.method.toUpperCase() : '';
  const subject = event.identity?.sub ?? event.subject;

  // 비정상 네트워크 신호 판별
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

  if (typeof subject !== 'string' || !subject) return null;

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

    const timestamp = typeof input.at === 'number' ? input.at : Date.parse(input.at);
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

      // 10분 구간 내에 확인된 가상 기기의 조회가 120건을 초과한 경우
      if (confirmedCount > LIMIT) {
        if (unusualCount > 0) {
          // 비정상 네트워크가 함께 있으면 복합 의심 제안을 즉시 반환
          return revocationProposal('unusual_network_burst_read', subject);
        }
        simpleCandidate ??= subject;
      }
    }
  }

  if (simpleCandidate) {
    return revocationProposal('burst_read', simpleCandidate);
  }

  return { action: 'observe' };
}