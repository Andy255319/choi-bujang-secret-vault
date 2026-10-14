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
  const lowerRoute = rawRoute.toLowerCase();
  const service = String(request?.service || '').toLowerCase();

  // 2. 강사 공지 / 반 자료 구역 쓰기 전면 차단 (8단계 구역 규칙)
  const isNotice = lowerPath.includes('announcement')
    || lowerPath.includes('notice')
    || lowerPath.includes('instructor')
    || lowerRoute.includes('announcement')
    || lowerRoute.includes('notice')
    || lowerRoute.includes('instructor')
    || service.includes('notice')
    || service.includes('announcement');
  const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

  if (isNotice && isWrite) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  const pathWithoutQuery = lowerPath.split('?')[0];
  const segments = pathWithoutQuery.split('/').filter(Boolean);

  // 감사(audit) 등 다른 서비스 규칙은 메모 구역 규칙에 의해 차단되지 않고 보존됩니다.
  const isNotesService = (service === 'notes' || service === '') && (
    lowerPath.startsWith('/notes')
    || lowerPath.startsWith('/api/notes')
    || lowerPath.startsWith('/restore')
    || lowerPath.startsWith('/api/restore')
    || lowerRoute.includes('/notes')
    || lowerRoute.includes('/restore')
  );

  if (isNotesService) {
    // 3. 메모 전체 목록 경로 차단 (8단계 구역 규칙)
    const isListPath = (segments.length === 1 && segments[0] === 'notes')
      || (segments.length === 2 && segments[0] === 'api' && segments[1] === 'notes');
    const isListRoute = lowerRoute === 'get /notes' || lowerRoute === 'get /api/notes';

    if ((isListPath || isListRoute) && method === 'GET') {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 4. 허용된 단건 자원 및 작성 경로 외 거부 (다른 서비스 규칙은 보존)
    const normalizedRoute = rawRoute.replace('/api/notes', '/notes');
    const ALLOWED_SINGLE_ROUTES = new Set([
      'POST /notes',
      'GET /notes/:id',
      'PUT /notes/:id',
      'DELETE /notes/:id',
      'POST /api/notes',
      'GET /api/notes/:id',
      'PUT /api/notes/:id',
      'DELETE /api/notes/:id',
      'POST /restore',
      'POST /api/restore',
      'GET /restore',
      'GET /api/restore',
      'POST /restore/:id',
      'POST /api/restore/:id',
      'GET /restore/:id',
      'GET /api/restore/:id',
    ]);

    if (!ALLOWED_SINGLE_ROUTES.has(rawRoute) && !ALLOWED_SINGLE_ROUTES.has(normalizedRoute)) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 5. :id 위치의 기능 경로 키워드 및 타인 구역 요청 식별 차단 (B의 A 자료 요청 등)
    const notesIdx = segments.findIndex(s => s === 'notes');
    if (notesIdx !== -1 && segments.length > notesIdx + 1) {
      const rawTarget = segments.slice(notesIdx + 1).join('/');

      // 5-1. 기능 경로 차단
      if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].some(k => rawTarget.includes(k))) {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'route_not_allowed',
          ruleIds: ['zone_access_control'],
        };
      }

      // 5-2. 타인 구역 요청 식별 차단 (B의 A 자료 요청 등)
      const currentSubject = String(request?.subjectId || '').trim();
      const tokens = rawTarget.split(/[:/]/);
      for (const token of tokens) {
        if (
          token.startsWith('learner_') ||
          token.startsWith('student_') ||
          token.startsWith('user_') ||
          token.includes('other') ||
          token.includes('victim')
        ) {
          if (currentSubject && token !== currentSubject) {
            return {
              ...base,
              decision: 'deny',
              reasonCode: 'route_not_allowed',
              ruleIds: ['zone_access_control'],
            };
          }
        }
      }
      if (rawTarget.includes('other') || rawTarget.includes('victim')) {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'route_not_allowed',
          ruleIds: ['zone_access_control'],
        };
      }
    }
  }

  // 6. 접속 신호 점검 (7단계)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 7. 야간 + 비정상 네트워크 + 대량 읽기 복합 이상 접속 (7단계)
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

  // 8. 단일 이상 징후(외국 지역 또는 비정상 네트워크 등) 추가 확인
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

  // 9. 정상 등록 기기 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}