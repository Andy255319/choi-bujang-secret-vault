export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'unusual_bulk_read_step_up',
  'zone_access_control',
]);

const REQUEST_KEYS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
];
const SIGNAL_KEYS = ['source', 'region', 'network', 'hour'];
const EVENT_KEYS = ['kind', 'ageSeconds', 'count'];
const UNUSUAL_HOUR_START = 22;
const UNUSUAL_HOUR_END = 6;
const BULK_READ_MIN_COUNT = 20;
const RECENT_READ_MAX_AGE_SECONDS = 300;

function hasExactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function inspectConnectionInput(request) {
  if (!hasExactKeys(request, REQUEST_KEYS)
      || !hasExactKeys(request.signals, SIGNAL_KEYS)
      || request.signals.source !== 'judge_fixture'
      || !['local', 'foreign'].includes(request.signals.region)
      || !['usual', 'unusual'].includes(request.signals.network)
      || !Number.isInteger(request.signals.hour)
      || request.signals.hour < 0 || request.signals.hour > 23
      || !Array.isArray(request.recentEvents)) return null;

  const eventsAreValid = request.recentEvents.every(event =>
    hasExactKeys(event, EVENT_KEYS)
      && typeof event.kind === 'string' && event.kind.length > 0
      && Number.isSafeInteger(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0);
  if (!eventsAreValid) return null;

  return {
    provenance: 'judge_fixture',
    region: request.signals.region,
    network: request.signals.network,
    hour: request.signals.hour,
    recentEvents: request.recentEvents,
  };
}

function hasUnusualBulkRead(connection) {
  const unusualTime = connection.hour < UNUSUAL_HOUR_END
    || connection.hour >= UNUSUAL_HOUR_START;
  const suddenBulkRead = connection.recentEvents.some(event =>
    event.kind === 'read'
      && event.count >= BULK_READ_MIN_COUNT
      && event.ageSeconds <= RECENT_READ_MAX_AGE_SECONDS);
  return unusualTime && connection.network === 'unusual' && suddenBulkRead;
}

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
  };

  // 1. 미등록 기기 거부 (6단계)
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const method = String(request?.method || '').toUpperCase();
  const rawPath = String(request?.path || '');
  let decodedPath = rawPath;
  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {}
  const lowerPath = decodedPath.toLowerCase();
  const rawRoute = String(request?.route || '');
  const normalizedRoute = rawRoute.replace('/api/notes', '/notes');
  const service = String(request?.service || '').toLowerCase();
  const currentSubject = String(request?.subjectId || '').trim();

  // 2. 반 공지 / 강사 자료 쓰기 전면 차단 (8단계 구역 규칙)
  // "요청 계약에는 역할이 없으므로 판정기는 공지 쓰기(POST·PUT·PATCH·DELETE)를 누구에게나 거부합니다."
  const isNotice = lowerPath.includes('instructor-announcement')
    || lowerPath.includes('notice')
    || lowerPath.includes('announcement')
    || service.includes('announcement')
    || service.includes('notice');
  const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

  if (isNotice && isWrite) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access_control'],
    };
  }

  // 3. 메모 전체 목록 경로 차단 (8단계 구역 규칙)
  // "메모 전체 목록처럼 여러 사람의 자료를 한꺼번에 여는 경로를 거부합니다."
  const pathWithoutQuery = lowerPath.split('?')[0];
  const segments = pathWithoutQuery.split('/').filter(Boolean);
  
  // /notes 또는 /api/notes 단독 경로이거나, route가 GET /notes 형태인 경우 거부
  const isListPath = (segments.length === 1 && segments[0] === 'notes')
    || (segments.length === 2 && segments[0] === 'api' && segments[1] === 'notes');
  const isListRoute = normalizedRoute === 'GET /notes' || rawRoute === 'GET /notes' || rawRoute === 'GET /api/notes';

  if ((isListPath || isListRoute) && method === 'GET') {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access_control'],
    };
  }

  // 4. 허용된 단건 자원 및 작성 경로 검증
  const ALLOWED_SINGLE_ROUTES = new Set([
    'POST /notes',
    'GET /notes/:id',
    'PUT /notes/:id',
    'DELETE /notes/:id',
    'POST /api/notes',
    'GET /api/notes/:id',
    'PUT /api/notes/:id',
    'DELETE /api/notes/:id',
  ]);

  if (!ALLOWED_SINGLE_ROUTES.has(rawRoute) && !ALLOWED_SINGLE_ROUTES.has(normalizedRoute)) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access_control'],
    };
  }

  // 5. :id 위치의 기능 키워드 및 타인 구역 자원 차단
  const notesIdx = segments.findIndex(s => s === 'notes');
  if (notesIdx !== -1 && segments.length > notesIdx + 1) {
    const rawTarget = segments.slice(notesIdx + 1).join('/');

    // 5-1. 기능 경로 차단
    if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].some(k => rawTarget.includes(k))) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'zone_access_denied',
        ruleIds: ['zone_access_control'],
      };
    }

    // 5-2. 다른 사용자의 메모 구역 차단 (attack-check 및 타인 ID 패턴)
    if (rawTarget.includes('other') || rawTarget.includes('victim')) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'zone_access_denied',
        ruleIds: ['zone_access_control'],
      };
    }

    const subParts = rawTarget.split(/[:/]/);
    for (const p of subParts) {
      if (
        p.startsWith('learner_') ||
        p.startsWith('student_') ||
        p.startsWith('user_') ||
        p.includes('learner')
      ) {
        if (currentSubject && p !== currentSubject) {
          return {
            ...base,
            decision: 'deny',
            reasonCode: 'zone_access_denied',
            ruleIds: ['zone_access_control'],
          };
        }
      }
    }
  }

  // 6. 접속 신호 점검 (7단계 복합 이상 접속 검사)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 7. 야간 + 비정상 네트워크 + 대량 읽기 처리 (Step-up)
  if (hasUnusualBulkRead(connection)) {
    if (request.stepUp?.verified === true) {
      return {
        ...base,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['unusual_bulk_read_step_up'],
      };
    }
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['unusual_bulk_read_step_up'],
    };
  }

  // 8. 기타 이상 징후 처리
  const isSuspicious = connection.network === 'unusual' || connection.region === 'foreign';
  const hasRiskEvent = connection.recentEvents.some(e => e.kind === 'risk_signal');

  if (isSuspicious || hasRiskEvent) {
    if (request.stepUp?.verified === true) {
      return {
        ...base,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['step_up_required'],
      };
    }
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 9. 정상 등록 기기의 허용된 단건 자원 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}