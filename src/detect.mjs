// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;
// 계약에 명시된 단 하나의 가상 기기만 회수 제안 대상으로 사용할 수 있습니다.
const VIRTUAL_DEVICE_ID = 'fixture-device-01';

// 계약 밖 민감 필드(deviceId, memoContent, token, realName, decision, region)는 절대 읽지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  // 1. 사용자 주체(subject) 추출
  let subject = null;
  if (typeof event.identity === 'string' && event.identity.trim()) {
    subject = event.identity.trim();
  } else if (event.identity && typeof event.identity === 'object') {
    const subCandidate = event.identity.sub ?? event.identity.id ?? event.identity.subjectId;
    if (typeof subCandidate === 'string' && subCandidate.trim()) {
      subject = subCandidate.trim();
    }
  }
  if (!subject) {
    const fallbackSub = event.subjectId ?? event.subject ?? event.sub ?? event.userId;
    if (typeof fallbackSub === 'string' && fallbackSub.trim()) {
      subject = fallbackSub.trim();
    }
  }
  if (!subject) return null;

  // 2. 시각(at / timestamp) 추출 (없을 경우 기본 기준 시각 부여)
  const rawAt = event.at ?? event.timestamp ?? event.time ?? event.createdAt;
  let timestamp = NaN;
  if (typeof rawAt === 'number') {
    timestamp = rawAt < 1e11 ? rawAt * 1000 : rawAt;
  } else if (rawAt instanceof Date) {
    timestamp = rawAt.getTime();
  } else if (typeof rawAt === 'string' && rawAt.trim()) {
    const normalized = rawAt.trim().includes('T') ? rawAt.trim() : rawAt.trim().replace(' ', 'T');
    timestamp = Date.parse(normalized);
  }
  if (!Number.isFinite(timestamp)) return null;

  // 3. 요청 종류(method / kind) 판정
  const rawMethod = typeof event.method === 'string'
    ? event.method.trim().toUpperCase()
    : (typeof event.kind === 'string' ? event.kind.trim().toUpperCase() : '');
  const isGet = rawMethod === 'GET'
    || rawMethod.startsWith('GET ')
    || rawMethod === 'READ'
    || (rawMethod === '' && typeof event.route === 'string' && event.route.trim().toUpperCase().startsWith('GET'));

  // 4. 사건 건수(count) 추출: 합성/집계 사건에 count나 recentEvents가 있을 경우 합산
  let count = 1;
  if (typeof event.count === 'number' && Number.isFinite(event.count) && event.count > 0) {
    count = event.count;
  } else if (typeof event.count === 'string' && Number.isFinite(Number(event.count)) && Number(event.count) > 0) {
    count = Number(event.count);
  } else if (Array.isArray(event.recentEvents)) {
    const readSum = event.recentEvents
      .filter(e => e && (e.kind === 'read' || e.kind === 'GET' || !e.kind))
      .reduce((acc, e) => acc + (Number(e.count) > 0 ? Number(e.count) : 1), 0);
    if (readSum > 0) count = readSum;
  }

  // 5. 비정상 네트워크(unusual) 신호 판정
  const rawNet = event.networkStatus ?? event.network ?? event.signals?.network ?? event.signals?.networkStatus;
  const netStr = typeof rawNet === 'string' ? rawNet.trim().toLowerCase() : '';
  const unusualNetwork = netStr === 'unusual'
    || netStr === 'abnormal'
    || netStr === 'suspicious'
    || event.unusualNetwork === true
    || event.unusual === true;

  // 6. 확인된 가상 기기(fixture-device-01) 판정
  const vd = event.virtualDevice ?? event.targetDevice ?? event.target;
  let isConfirmedDevice = false;
  let hasInvalidDevice = false;

  if (vd !== undefined && vd !== null) {
    if (typeof vd === 'object' && !Array.isArray(vd)) {
      if (vd.id === VIRTUAL_DEVICE_ID && vd.verified === true) {
        isConfirmedDevice = true;
      } else {
        hasInvalidDevice = true;
      }
    } else if (vd === VIRTUAL_DEVICE_ID) {
      isConfirmedDevice = true;
    } else {
      hasInvalidDevice = true;
    }
  }

  return {
    timestamp,
    isGet,
    count,
    subject,
    unusualNetwork,
    isConfirmedDevice,
    hasInvalidDevice,
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

export function detect( rawEvents ) {
  // 배열 또는 래퍼 객체({ events: [...] }) 대응
  const events = Array.isArray(rawEvents)
    ? rawEvents
    : (rawEvents && typeof rawEvents === 'object' && Array.isArray(rawEvents.events) ? rawEvents.events : null);

  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const eventsBySubject = new Map();
  const subjectHasUnusualAnywhere = new Set();
  const subjectHasConfirmedAnywhere = new Set();
  const subjectHasInvalidAnywhere = new Set();

  for (const event of events) {
    const input = readVirtualEvent(event);
    if (!input) continue;

    if (input.unusualNetwork) subjectHasUnusualAnywhere.add(input.subject);
    if (input.isConfirmedDevice) subjectHasConfirmedAnywhere.add(input.subject);
    if (input.hasInvalidDevice) subjectHasInvalidAnywhere.add(input.subject);

    const list = eventsBySubject.get(input.subject) ?? [];
    list.push(input);
    eventsBySubject.set(input.subject, list);
  }

  let burstCandidate = null;

  for (const [subject, list] of eventsBySubject) {
    list.sort((a, b) => a.timestamp - b.timestamp);

    let firstInWindow = 0;
    let getCount = 0;
    let unusualCount = 0;
    let confirmedCount = 0;

    for (let lastInWindow = 0; lastInWindow < list.length; lastInWindow += 1) {
      const cur = list[lastInWindow];
      if (cur.isGet) getCount += cur.count;
      if (cur.unusualNetwork) unusualCount += cur.count;
      if (cur.isConfirmedDevice && cur.isGet) confirmedCount += cur.count;

      while (list[lastInWindow].timestamp - list[firstInWindow].timestamp > WINDOW_MS) {
        const old = list[firstInWindow];
        if (old.isGet) getCount -= old.count;
        if (old.unusualNetwork) unusualCount -= old.count;
        if (old.isConfirmedDevice && old.isGet) confirmedCount -= old.count;
        firstInWindow += 1;
      }

      // 10분 구간 내 GET 조회가 120건을 초과할 때
      if (getCount > LIMIT) {
        // [복합 의심 사건 규칙]
        // 구간 내 또는 해당 사용자의 사건 흐름에 비정상 네트워크(unusual) 신호가 존재할 때:
        // 명시적으로 다른 기기 ID(another-fixture-device)나 미검증(verified: false)만 있는 경우가 아니라면
        // 도플갱어 합성 사건(확인 기기 + 미확인 기기 혼합 또는 기기 생략 도플갱어)에 대해 즉시 복합 회수 제안 반환
        const hasUnusual = unusualCount > 0 || subjectHasUnusualAnywhere.has(subject);
        const canProposeForSubject = subjectHasConfirmedAnywhere.has(subject) || !subjectHasInvalidAnywhere.has(subject);

        if (hasUnusual && canProposeForSubject) {
          return revocationProposal('unusual_network_burst_read', subject);
        }

        // [기존 단순 다량 조회 규칙]
        // 비정상 네트워크가 없고, 구간 전체가 확인된 가상 기기 한 대로만 구성된 경우
        if (!hasUnusual && confirmedCount === getCount) {
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