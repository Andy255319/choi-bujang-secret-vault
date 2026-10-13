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

  return { timestamp, isGet: method === 'GET', subject, unusualNetwork, isConfirmedDevice };
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

  // 사용자별 사건 목록 및 확인된 가상 기기 보유 여부 식별
  const eventsBySubject = new Map();
  const confirmedSubjects = new Set();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    if (input.isConfirmedDevice) {
      confirmedSubjects.add(input.subject);
    }

    const list = eventsBySubject.get(input.subject) ?? [];
    list.push(input);
    eventsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of eventsBySubject) {
    const hasConfirmedDevice = confirmedSubjects.has(subject);
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
        // [복합 의심 규칙]: 비정상 네트워크 신호가 동반되고, 해당 사용자의 확인된 기기가 존재하는 경우
        // 도플갱어 공격으로 공격자의 미확인 기기 요청만으로 다량 조회가 발생해도
        // 사용자의 확인된 가상 기기(fixture-device-01) 회수 제안을 즉시 반환합니다.
        if (unusualCount > 0 && hasConfirmedDevice) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [기존 단순 다량 조회 규칙]: 이상 네트워크가 없고, 구간 전체 조회가 확인된 기기 한 대로만 구성된 경우
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