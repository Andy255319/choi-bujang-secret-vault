// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약 밖 필드(deviceId, memoContent, token, realName, decision, region)는 건드리지 않고
// 계약에 명시된 필수 5개 필드만 안전하게 읽습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = event.method;
  const identity = event.identity;
  const subject = identity !== null && typeof identity === 'object' ? identity.sub : null;
  const networkStatus = event.networkStatus;
  const unusualNetwork = networkStatus === 'unusual';
  const virtualDevice = event.virtualDevice;

  const isConfirmedDevice = virtualDevice !== null
    && typeof virtualDevice === 'object'
    && !Array.isArray(virtualDevice)
    && virtualDevice.verified === true
    && virtualDevice.id === VIRTUAL_DEVICE_ID;

  if (typeof subject !== 'string' || !subject || typeof at !== 'string') return null;

  const timestamp = Date.parse(at);
  if (!Number.isFinite(timestamp)) return null;

  return {
    timestamp,
    isGet: method === 'GET',
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

  const readsBySubject = new Map();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input || !input.isGet) continue;

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
        // [1. 복합 의심 사건 규칙: 합성 도플갱어 접속 사건 대응]
        // 비정상 네트워크(unusual) 신호가 섞여 있다면 도플갱어의 요청에 기기 식별값이 없더라도
        // 계정 소유자의 가상 기기(fixture-device-01)에 대해 즉시 회수 제안을 반환합니다.
        if (unusualCount > 0) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [2. 기존 단순 다량 조회 규칙]
        // 이상 네트워크가 없는 순수 다량 조회는 오직 '확인된 가상 기기 한 대'로만 100% 구성되었을 때만 후보 등록
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