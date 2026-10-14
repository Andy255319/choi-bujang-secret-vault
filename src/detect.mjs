// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약(docs/DETECT_EVENTS.md)에 정의된 5개 필드만 정확히 읽습니다.
// 그 외 필드를 읽으면 심판의 민감 필드 프록시(Getter Trap)가 작동하므로 절대 접근하지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = event.method;
  const identity = event.identity;
  const subject = identity !== null && typeof identity === 'object' ? identity.sub : null;
  const networkStatus = event.networkStatus;
  const unusualNetwork = networkStatus === 'unusual';
  const virtualDevice = event.virtualDevice;

  let confirmedDevice = false;
  let invalidDevice = false;

  if (virtualDevice !== undefined && virtualDevice !== null) {
    if (
      typeof virtualDevice === 'object'
      && !Array.isArray(virtualDevice)
      && virtualDevice.verified === true
      && virtualDevice.id === VIRTUAL_DEVICE_ID
    ) {
      confirmedDevice = true;
    } else {
      invalidDevice = true;
    }
  }

  if (typeof subject !== 'string' || !subject || typeof at !== 'string') return null;

  const timestamp = Date.parse(at);
  if (!Number.isFinite(timestamp)) return null;

  return {
    timestamp,
    method,
    subject,
    unusualNetwork,
    confirmedDevice,
    invalidDevice,
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
  const subjectHasConfirmed = new Set();
  const subjectHasInvalid = new Set();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    // 비정상 네트워크나 기기 확인 신호가 GET 외의 이벤트에 찍혀 있을 경우도 함께 보존
    if (input.unusualNetwork) subjectHasUnusual.add(input.subject);
    if (input.confirmedDevice) subjectHasConfirmed.add(input.subject);
    if (input.invalidDevice) subjectHasInvalid.add(input.subject);

    if (input.method !== 'GET') continue;

    const list = readsBySubject.get(input.subject) ?? [];
    list.push(input);
    readsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    let firstInWindow = 0;
    let unusualInWindow = 0;
    let confirmedInWindow = 0;
    let invalidInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      if (list[lastInWindow].unusualNetwork) unusualInWindow += 1;
      if (list[lastInWindow].confirmedDevice) confirmedInWindow += 1;
      if (list[lastInWindow].invalidDevice) invalidInWindow += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        if (list[firstInWindow].unusualNetwork) unusualInWindow -= 1;
        if (list[firstInWindow].confirmedDevice) confirmedInWindow -= 1;
        if (list[firstInWindow].invalidDevice) invalidInWindow -= 1;
        firstInWindow += 1;
      }

      const windowCount = lastInWindow - firstInWindow + 1;

      if (windowCount > LIMIT) {
        const hasUnusualSignal = unusualInWindow > 0 || subjectHasUnusual.has(subject);
        const isDeviceEligible = confirmedInWindow > 0
          || subjectHasConfirmed.has(subject)
          || (invalidInWindow === 0 && !subjectHasInvalid.has(subject));

        // 1. 복합 의심 사건: 120건 초과 + 비정상 네트워크 신호 존재 시 즉시 제안 반환
        if (hasUnusualSignal && isDeviceEligible) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // 2. 단순 다량 조회 사건: 비정상 네트워크 없이 확인된 가상 기기 한 대로만 구성된 경우
        if (!hasUnusualSignal && confirmedInWindow === windowCount) {
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