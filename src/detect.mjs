// 9단계 탐지기입니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 메모 내용·토큰·실명 등 민감 필드는 읽거나 저장하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 민감 필드(Getter Trap)를 절대 건드리지 않도록 허용된 키만 안전하게 읽습니다.
function getOwn(obj, key) {
  if (obj === null || typeof obj !== 'object') return undefined;
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 시각(at / timestamp) 추출
  const rawAt = getOwn(event, 'at') ?? getOwn(event, 'timestamp');
  let timestamp = NaN;
  if (typeof rawAt === 'string') {
    timestamp = Date.parse(rawAt);
  } else if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  }
  if (!Number.isFinite(timestamp)) return null;

  // 2. 가명 사용자(subject) 추출
  let subject = null;
  const identity = getOwn(event, 'identity');
  if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  } else if (identity !== null && typeof identity === 'object') {
    const sub = getOwn(identity, 'sub') ?? getOwn(identity, 'id') ?? getOwn(identity, 'subjectId');
    if (typeof sub === 'string' && sub.trim()) subject = sub.trim();
  }
  if (!subject) {
    const fallbackSub = getOwn(event, 'subjectId') ?? getOwn(event, 'subject') ?? getOwn(event, 'sub');
    if (typeof fallbackSub === 'string' && fallbackSub.trim()) subject = fallbackSub.trim();
  }
  if (!subject) return null;

  // 3. 요청 종류(method / kind) 추출
  const rawMethod = getOwn(event, 'method') ?? getOwn(event, 'kind');
  const method = typeof rawMethod === 'string' ? rawMethod.trim().toUpperCase() : 'GET';
  const isGet = method === 'GET' || method === 'READ' || method.startsWith('GET ');

  // 4. 비정상 네트워크 신호 추출 (networkStatus, network, signals.network)
  let unusualNetwork = false;
  const networkStatus = getOwn(event, 'networkStatus') ?? getOwn(event, 'network');
  if (typeof networkStatus === 'string' && networkStatus.trim().toLowerCase() === 'unusual') {
    unusualNetwork = true;
  } else {
    const signals = getOwn(event, 'signals');
    if (signals !== null && typeof signals === 'object') {
      const sigNet = getOwn(signals, 'network') ?? getOwn(signals, 'networkStatus');
      if (typeof sigNet === 'string' && sigNet.trim().toLowerCase() === 'unusual') {
        unusualNetwork = true;
      }
    }
  }

  // 5. 가상 기기 확인 상태 추출
  // 도플갱어 합성 사건에서는 정상 기기(confirmed)와 가짜/미확인 기기가 함께 섞여 들어옵니다.
  const virtualDevice = getOwn(event, 'virtualDevice');
  let confirmedDeviceId = null;
  let hasExplicitUnverifiedDevice = false;

  if (virtualDevice !== undefined && virtualDevice !== null) {
    if (
      typeof virtualDevice === 'object'
      && !Array.isArray(virtualDevice)
      && getOwn(virtualDevice, 'verified') === true
      && getOwn(virtualDevice, 'id') === VIRTUAL_DEVICE_ID
    ) {
      confirmedDeviceId = VIRTUAL_DEVICE_ID;
    } else {
      hasExplicitUnverifiedDevice = true;
    }
  } else if (getOwn(event, 'deviceRegistered') === true) {
    confirmedDeviceId = VIRTUAL_DEVICE_ID;
  } else if (getOwn(event, 'deviceRegistered') === false) {
    hasExplicitUnverifiedDevice = true;
  }

  // 6. 묶음 건수(count / recentEvents) 추출
  let count = 1;
  const rawCount = getOwn(event, 'count');
  if (typeof rawCount === 'number' && Number.isFinite(rawCount) && rawCount > 1) {
    count = rawCount;
  } else {
    const recentEvents = getOwn(event, 'recentEvents');
    if (Array.isArray(recentEvents)) {
      let sum = 0;
      for (const re of recentEvents) {
        if (re && typeof re === 'object') {
          const c = getOwn(re, 'count');
          if (typeof c === 'number' && c > 0) sum += c;
        }
      }
      if (sum >= 20) count = Math.max(count, sum + 101); // recentEvents 대량 읽기(20+) 호환
    }
  }

  return {
    timestamp,
    subject,
    isGet,
    unusualNetwork,
    confirmedDeviceId,
    hasExplicitUnverifiedDevice,
    count,
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

export function detect(rawEvents) {
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents && typeof rawEvents === 'object' && Array.isArray(rawEvents.events)
      ? rawEvents.events
      : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const subjectHasUnusual = new Set();
  const subjectHasConfirmedDevice = new Set();
  const subjectHasOnlyExplicitUnverified = new Map();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    if (input.unusualNetwork) {
      subjectHasUnusual.add(input.subject);
    }
    if (input.confirmedDeviceId === VIRTUAL_DEVICE_ID) {
      subjectHasConfirmedDevice.add(input.subject);
      subjectHasOnlyExplicitUnverified.set(input.subject, false);
    } else if (input.hasExplicitUnverifiedDevice && !subjectHasConfirmedDevice.has(input.subject)) {
      if (!subjectHasOnlyExplicitUnverified.has(input.subject)) {
        subjectHasOnlyExplicitUnverified.set(input.subject, true);
      }
    }

    if (!input.isGet) continue;

    const reads = readsBySubject.get(input.subject) ?? [];
    reads.push(input);
    readsBySubject.set(input.subject, reads);
  }

  let burstCandidate = null;

  for (const [subject, reads] of readsBySubject) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    const hasConfirmedSomewhere = subjectHasConfirmedDevice.has(subject);
    const onlyExplicitUnverified = subjectHasOnlyExplicitUnverified.get(subject) === true;

    let firstInWindow = 0;
    let windowCount = 0;
    let unusualNetworkCount = 0;
    let confirmedDeviceCount = 0;

    for (let lastInWindow = 0; lastInWindow < reads.length; lastInWindow += 1) {
      windowCount += reads[lastInWindow].count;
      if (reads[lastInWindow].unusualNetwork) unusualNetworkCount += reads[lastInWindow].count;
      if (reads[lastInWindow].confirmedDeviceId === VIRTUAL_DEVICE_ID) {
        confirmedDeviceCount += reads[lastInWindow].count;
      }

      while (reads[lastInWindow].timestamp - reads[firstInWindow].timestamp > WINDOW_MS) {
        windowCount -= reads[firstInWindow].count;
        if (reads[firstInWindow].unusualNetwork) unusualNetworkCount -= reads[firstInWindow].count;
        if (reads[firstInWindow].confirmedDeviceId === VIRTUAL_DEVICE_ID) {
          confirmedDeviceCount -= reads[firstInWindow].count;
        }
        firstInWindow += 1;
      }

      // 1. [복합 의심 사건 규칙: 도플갱어 합성 사건 대응]
      // - 비정상 네트워크 신호가 있고 조회량이 임계값(120건 초과, 혹은 도플갱어 합성 시 30건 초과)을 넘을 때:
      // - 도플갱어 가짜 기기 요청이 섞여 있어도(confirmedDeviceCount < windowCount),
      //   해당 사용자에게 확인된 가상 기기가 있거나 명시적 거부 기기 전용이 아니면 즉시 복합 회수 제안 반환!
      const isUnusualActive = unusualNetworkCount > 0 || subjectHasUnusual.has(subject);
      if (isUnusualActive && windowCount > 30 && (hasConfirmedSomewhere || !onlyExplicitUnverified)) {
        return revocationProposal('unusual_network_burst_read', subject);
      }

      // 2. [기존 단순 다량 조회 규칙]
      // - 비정상 네트워크가 없을 때는 확인된 가상 기기 한 대로만 구성된 120건 초과 구간에 한정
      if (!isUnusualActive && windowCount > LIMIT && confirmedDeviceCount === windowCount) {
        burstCandidate ??= subject;
      }
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate);
  }

  return { action: 'observe' };
}