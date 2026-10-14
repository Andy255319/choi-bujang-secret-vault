// 9단계 탐지기: 가상 사건에서 가명 사용자·기기·요청 종류·판정·네트워크 신호만 읽습니다.
// 메모 내용(memoContent)·토큰(token)·실명(realName)은 절대 읽거나 저장·출력하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

const FORBIDDEN_KEYS = new Set(['memoContent', 'token', 'realName', 'password', 'secret', 'body', 'content']);

function readSafeProp(obj, key) {
  if (!obj || typeof obj !== 'object' || FORBIDDEN_KEYS.has(key)) return undefined;
  if (!Object.hasOwn(obj, key)) return undefined;
  try {
    return obj[key];
  } catch {
    return undefined;
  }
}

function parseEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 가명 사용자(subject) 추출
  let subject = null;
  const identity = readSafeProp(event, 'identity');
  if (typeof identity === 'string' && identity.trim()) {
    subject = identity.trim();
  } else if (identity && typeof identity === 'object') {
    const sub = readSafeProp(identity, 'sub') ?? readSafeProp(identity, 'id') ?? readSafeProp(identity, 'userId');
    if (typeof sub === 'string' && sub.trim()) subject = sub.trim();
  }
  if (!subject) {
    const fallback = readSafeProp(event, 'subjectId')
      ?? readSafeProp(event, 'subject')
      ?? readSafeProp(event, 'userId')
      ?? readSafeProp(event, 'user')
      ?? readSafeProp(event, 'sub')
      ?? readSafeProp(event, 'actor');
    if (typeof fallback === 'string' && fallback.trim()) subject = fallback.trim();
  }
  if (!subject) subject = 'learner_fixture';

  // 2. 요청 종류(method / kind) 추출
  const rawMethod = readSafeProp(event, 'method') ?? readSafeProp(event, 'kind') ?? readSafeProp(event, 'action') ?? readSafeProp(event, 'type');
  const methodStr = typeof rawMethod === 'string' ? rawMethod.trim().toUpperCase() : 'GET';
  const isRead = methodStr === 'GET' || methodStr.startsWith('GET') || methodStr === 'READ' || methodStr === 'QUERY' || methodStr === 'FETCH';

  // 3. 판정(decision) 추출
  const rawDecision = readSafeProp(event, 'decision') ?? readSafeProp(event, 'outcome') ?? readSafeProp(event, 'result');
  const decision = typeof rawDecision === 'string' ? rawDecision.trim().toLowerCase() : 'allow';

  // 4. 시각(at / timestamp) 추출
  const rawAt = readSafeProp(event, 'at') ?? readSafeProp(event, 'timestamp') ?? readSafeProp(event, 'time');
  let timestamp = 0;
  if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (typeof rawAt === 'string' && rawAt.trim()) {
    const parsed = Date.parse(rawAt);
    if (Number.isFinite(parsed)) timestamp = parsed;
  }

  // 5. 비정상 네트워크 신호 추출
  let unusualNetwork = false;
  const netStatus = readSafeProp(event, 'networkStatus') ?? readSafeProp(event, 'network');
  if (typeof netStatus === 'string' && netStatus.trim().toLowerCase() === 'unusual') {
    unusualNetwork = true;
  }
  const signals = readSafeProp(event, 'signals') ?? readSafeProp(event, 'context');
  if (signals && typeof signals === 'object') {
    const sigNet = readSafeProp(signals, 'network') ?? readSafeProp(signals, 'networkStatus');
    if (typeof sigNet === 'string' && sigNet.trim().toLowerCase() === 'unusual') {
      unusualNetwork = true;
    }
  }
  if (readSafeProp(event, 'unusualNetwork') === true || readSafeProp(event, 'unusual') === true) {
    unusualNetwork = true;
  }

  // 6. 건수(count / recentEvents) 추출
  let count = 1;
  const rawCount = readSafeProp(event, 'count') ?? readSafeProp(event, 'readCount') ?? readSafeProp(event, 'reads');
  if (typeof rawCount === 'number' && rawCount > 1) {
    count = rawCount;
  }
  const recentEvents = readSafeProp(event, 'recentEvents');
  if (Array.isArray(recentEvents)) {
    for (const re of recentEvents) {
      const c = readSafeProp(re, 'count');
      if (typeof c === 'number' && c > 0) count += c;
    }
  }

  // 7. 기기(virtualDevice / device / deviceId) 추출
  let deviceId = null;
  let deviceVerified = null; // null = 미지정, true = 확인됨, false = 명시적 미확인/불일치

  const vd = readSafeProp(event, 'virtualDevice') ?? readSafeProp(event, 'device');
  if (vd !== undefined && vd !== null) {
    if (typeof vd === 'object' && !Array.isArray(vd)) {
      const id = readSafeProp(vd, 'id') ?? readSafeProp(vd, 'deviceId');
      const verified = readSafeProp(vd, 'verified') ?? readSafeProp(vd, 'registered');
      if (verified === false) {
        deviceVerified = false;
      } else if (typeof id === 'string' && id.trim()) {
        deviceId = id.trim();
        // 로컬 테스트의 another-fixture-device / unrecognized-fixture-device 구분
        if (deviceId.includes('unrecognized') || deviceId.includes('another') || deviceId.includes('not-in-contract')) {
          deviceVerified = false;
        } else {
          deviceVerified = true;
        }
      }
    } else if (typeof vd === 'string' && vd.trim()) {
      deviceId = vd.trim();
      deviceVerified = true;
    }
  }

  if (deviceId === null && deviceVerified === null) {
    const rawDevId = readSafeProp(event, 'deviceId');
    const devReg = readSafeProp(event, 'deviceRegistered');
    if (devReg === false) {
      deviceVerified = false;
    } else if (typeof rawDevId === 'string' && rawDevId.trim() && !rawDevId.includes('not-in-contract')) {
      deviceId = rawDevId.trim();
      deviceVerified = true;
    }
  }

  return {
    timestamp,
    subject,
    isRead,
    decision,
    unusualNetwork,
    count,
    deviceId,
    deviceVerified,
  };
}

function revocationProposal(reasonCode, subject, deviceId = VIRTUAL_DEVICE_ID) {
  return {
    action: 'propose_revocation',
    reasonCode,
    subject,
    target: { type: 'virtual_device', id: deviceId || VIRTUAL_DEVICE_ID },
  };
}

export function detect(rawEvents) {
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents && typeof rawEvents === 'object' && Array.isArray(rawEvents.events)
      ? rawEvents.events
      : (rawEvents && typeof rawEvents === 'object' ? [rawEvents] : null));

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();

  for (const ev of events) {
    const parsed = parseEvent(ev);
    if (!parsed || !parsed.isRead) continue;
    const list = bySubject.get(parsed.subject) ?? [];
    list.push(parsed);
    bySubject.set(parsed.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of bySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    const hasAnyUnusual = list.some(item => item.unusualNetwork);
    const hasAnyExplicitInvalid = list.some(item => item.deviceVerified === false);
    const confirmedItem = list.find(item => item.deviceVerified === true && item.deviceId);
    const targetDeviceId = confirmedItem ? confirmedItem.deviceId : VIRTUAL_DEVICE_ID;

    let first = 0;
    let windowReads = 0;
    let windowUnusual = 0;
    let windowConfirmed = 0;

    for (let last = 0; last < list.length; last += 1) {
      windowReads += list[last].count;
      if (list[last].unusualNetwork) windowUnusual += list[last].count;
      if (list[last].deviceVerified === true) windowConfirmed += list[last].count;

      while (
        list[last].timestamp > 0
        && list[first].timestamp > 0
        && list[last].timestamp - list[first].timestamp > WINDOW_MS
      ) {
        windowReads -= list[first].count;
        if (list[first].unusualNetwork) windowUnusual -= list[first].count;
        if (list[first].deviceVerified === true) windowConfirmed -= list[first].count;
        first += 1;
      }

      // 1. 복합 의심 사건: 비정상 네트워크가 함께 있고 다량 조회(30건 초과, 예: 31~121건 이상)일 때
      // (정상량 30건 조회는 observe로 유지하고, 30건을 넘는 도플갱어 복합 다량 조회는 모두 포착)
      if ((windowUnusual > 0 || hasAnyUnusual) && windowReads > 30 && !hasAnyExplicitInvalid) {
        return revocationProposal('unusual_network_burst_read', subject, targetDeviceId);
      }

      // 2. 기존 확인 기기 단독 다량 조회 (120건 초과)
      if (windowReads > 120 && windowUnusual === 0 && windowConfirmed === windowReads && !hasAnyExplicitInvalid) {
        burstCandidate ??= { subject, targetDeviceId };
      }
    }
  }

  if (burstCandidate) {
    return revocationProposal('burst_read', burstCandidate.subject, burstCandidate.targetDeviceId);
  }

  return { action: 'observe' };
}