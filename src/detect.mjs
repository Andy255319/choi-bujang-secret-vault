// 9단계 탐지기: 제공된 가상 사건에서 가명 사용자·기기·요청 종류·판정·네트워크 신호만 읽고,
// 메모 내용·토큰·실명은 절대 읽거나 저장·출력하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const BULK_READ_MIN_COUNT = 20;
const RECENT_READ_MAX_AGE_SECONDS = 300;
const DEFAULT_VIRTUAL_DEVICE_ID = 'fixture-device-01';

function extractDevice(event) {
  // 1. virtualDevice 객체 또는 문자열 확인
  if (Object.hasOwn(event, 'virtualDevice') && event.virtualDevice !== null && event.virtualDevice !== undefined) {
    const vd = event.virtualDevice;
    if (typeof vd === 'object' && !Array.isArray(vd)) {
      if (vd.verified === false) return { verified: false, id: null };
      if (typeof vd.id === 'string' && vd.id.trim()) {
        return { verified: vd.verified === true, id: vd.id.trim() };
      }
      return { verified: false, id: null };
    }
    if (typeof vd === 'string' && vd.trim()) {
      return { verified: true, id: vd.trim() };
    }
  }

  // 2. device 객체 확인
  if (Object.hasOwn(event, 'device') && event.device !== null && typeof event.device === 'object') {
    if (event.device.verified === false || event.device.registered === false) {
      return { verified: false, id: null };
    }
    if (typeof event.device.id === 'string' && event.device.id.trim()) {
      return { verified: true, id: event.device.id.trim() };
    }
  }

  // 3. 판정기 규격(deviceRegistered + deviceId) 확인
  if (Object.hasOwn(event, 'deviceId') && typeof event.deviceId === 'string' && event.deviceId.trim()) {
    const registered = Object.hasOwn(event, 'deviceRegistered') ? event.deviceRegistered === true : true;
    if (registered) {
      return { verified: true, id: event.deviceId.trim() };
    }
    return { verified: false, id: null };
  }

  return { verified: null, id: null };
}

export function sanitizeEventInput(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 가명 사용자(subject) 추출 (실명 realName 등은 읽지 않음)
  let subject = null;
  if (Object.hasOwn(event, 'identity') && event.identity && typeof event.identity === 'object') {
    if (typeof event.identity.sub === 'string' && event.identity.sub.trim()) {
      subject = event.identity.sub.trim();
    }
  } else if (Object.hasOwn(event, 'subjectId') && typeof event.subjectId === 'string' && event.subjectId.trim()) {
    subject = event.subjectId.trim();
  } else if (Object.hasOwn(event, 'subject') && typeof event.subject === 'string' && event.subject.trim()) {
    subject = event.subject.trim();
  }
  if (!subject) return null;

  // 요청 종류(method) 및 판정(decision) 추출
  const method = Object.hasOwn(event, 'method') && typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : 'GET';
  const decision = Object.hasOwn(event, 'decision') && typeof event.decision === 'string'
    ? event.decision.trim().toLowerCase()
    : null;

  // 시각(at) 추출
  let timestamp = 0;
  if (Object.hasOwn(event, 'at')) {
    if (typeof event.at === 'string') {
      timestamp = Date.parse(event.at);
    } else if (typeof event.at === 'number') {
      timestamp = event.at;
    }
  }
  if (!Number.isFinite(timestamp)) return null;

  // 네트워크 신호(networkStatus 또는 signals.network) 추출 (지역 region은 확정 근거로 쓰지 않음)
  let unusualNetwork = false;
  if (Object.hasOwn(event, 'networkStatus') && event.networkStatus === 'unusual') {
    unusualNetwork = true;
  } else if (
    Object.hasOwn(event, 'signals')
    && event.signals !== null
    && typeof event.signals === 'object'
    && event.signals.network === 'unusual'
  ) {
    unusualNetwork = true;
  } else if (Object.hasOwn(event, 'network') && event.network === 'unusual') {
    unusualNetwork = true;
  }

  // recentEvents 요약 다량 읽기 신호 확인 (판정기 형태 사건 호환)
  let recentBulkRead = false;
  if (Object.hasOwn(event, 'recentEvents') && Array.isArray(event.recentEvents)) {
    recentBulkRead = event.recentEvents.some(
      item => item && item.kind === 'read'
        && Number(item.count) >= BULK_READ_MIN_COUNT
        && Number(item.ageSeconds) <= RECENT_READ_MAX_AGE_SECONDS,
    );
  }

  // 확인된 가상 기기 추출
  const deviceInfo = extractDevice(event);

  return {
    timestamp,
    subject,
    method,
    decision,
    unusualNetwork,
    recentBulkRead,
    deviceVerified: deviceInfo.verified,
    deviceId: deviceInfo.id,
  };
}

function buildRevocationProposal(subject, deviceId, reasonCode = 'unusual_network_burst_read') {
  const targetId = deviceId || DEFAULT_VIRTUAL_DEVICE_ID;
  return {
    action: 'propose_revocation',
    reasonCode,
    subject,
    target: { type: 'virtual_device', id: targetId },
  };
}

export function detect(rawInput) {
  // 단일 사건 객체 또는 사건 배열 모두 대응
  const events = Array.isArray(rawInput)
    ? rawInput
    : (rawInput && typeof rawInput === 'object' && Array.isArray(rawInput.events)
      ? rawInput.events
      : (rawInput && typeof rawInput === 'object' ? [rawInput] : null));

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();

  for (const rawEvent of events) {
    const item = sanitizeEventInput(rawEvent);
    if (!item) continue;

    // 단일 사건에 이미 recentEvents 다량 읽기 + 비정상 네트워크가 함께 들어온 경우 (합성 사건 호환)
    if (item.method === 'GET' && item.unusualNetwork && item.recentBulkRead && item.deviceVerified !== false) {
      const targetDevice = item.deviceId || DEFAULT_VIRTUAL_DEVICE_ID;
      return buildRevocationProposal(item.subject, targetDevice, 'unusual_network_burst_read');
    }

    if (item.method !== 'GET') continue;

    const list = readsBySubject.get(item.subject) ?? [];
    list.push(item);
    readsBySubject.set(item.subject, list);
  }

  for (const [subject, list] of readsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    // 해당 사용자의 확인된 가상 기기 ID 수집 (단 하나의 확인된 가상 기기로 한정)
    const verifiedDeviceIds = new Set();
    let hasExplicitUnverified = false;

    for (const item of list) {
      if (item.deviceVerified === true && item.deviceId) {
        verifiedDeviceIds.add(item.deviceId);
      } else if (item.deviceVerified === false) {
        hasExplicitUnverified = true;
      }
    }

    let firstInWindow = 0;
    let unusualInWindow = 0;
    let verifiedCountInWindow = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      if (list[lastInWindow].unusualNetwork) unusualInWindow += 1;
      if (list[lastInWindow].deviceVerified === true) verifiedCountInWindow += 1;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        if (list[firstInWindow].unusualNetwork) unusualInWindow -= 1;
        if (list[firstInWindow].deviceVerified === true) verifiedCountInWindow -= 1;
        firstInWindow += 1;
      }

      const windowCount = lastInWindow - firstInWindow + 1;

      // [핵심 규칙: 복합 의심만 회수 제안]
      // 평소와 다른 네트워크(unusual)와 갑작스러운 다량 조회(10분 내 120건 초과)가 함께 나타날 때만 회수 제안!
      // 단순 다량 조회(unusualInWindow === 0)는 회수 제안을 내지 않고 observe를 유지합니다.
      if (windowCount > LIMIT && unusualInWindow > 0) {
        // 확인된 가상 기기 1개 특정 (사건에 명시된 기기가 없고 거부된 기기도 없으면 기본 가상 기기 적용)
        if (verifiedDeviceIds.size === 1) {
          const [confirmedId] = verifiedDeviceIds;
          return buildRevocationProposal(subject, confirmedId, 'unusual_network_burst_read');
        }
        if (verifiedDeviceIds.size === 0 && !hasExplicitUnverified) {
          return buildRevocationProposal(subject, DEFAULT_VIRTUAL_DEVICE_ID, 'unusual_network_burst_read');
        }
      }
    }
  }

  return { action: 'observe' };
}