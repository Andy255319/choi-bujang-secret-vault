import { parseResourceId, parseMemoResourceId } from './resource-id.mjs';

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

// 메모 전체 목록(GET /notes)은 여러 사람의 자료가 섞일 수 있어 판정기에서 닫고,
// 단건 자원과 작성 요청만 허용합니다.
const ALLOWED_ROUTES = new Set([
  'POST /notes',
  'GET /notes/:id',
  'PUT /notes/:id',
  'DELETE /notes/:id',
]);

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

  const rawPath = String(request?.path || '');
  let decodedPath = rawPath;
  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {}
  const lowerPath = decodedPath.toLowerCase();
  const method = String(request?.method || '').toUpperCase();

  // 2. 강사 공지·반 자료 구역 쓰기 차단 (8단계 구역 규칙)
  // "판정기는 공지 쓰기(POST·PUT·PATCH·DELETE)를 누구에게나 거부합니다."
  const isNoticeResource = lowerPath.includes('instructor-announcement')
    || lowerPath.includes('notice')
    || lowerPath.includes('announcement');
  const isWriteMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

  if (isNoticeResource && isWriteMethod) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access_control'],
    };
  }

  // 3. 알 수 없는 경로 및 메모 전체 목록(GET /notes) 거부
  // "메모 전체 목록처럼 여러 사람의 자료를 한꺼번에 여는 경로를 허용하면 안 됨"
  const normalizedRoute = (request?.route || '').replace('/api/notes', '/notes');
  if (normalizedRoute === 'GET /notes' || request?.route === 'GET /notes') {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'zone_access_denied',
      ruleIds: ['zone_access_control'],
    };
  }

  if (!ALLOWED_ROUTES.has(request?.route) && !ALLOWED_ROUTES.has(normalizedRoute)) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  // 4. 경로 세부 파싱 (:id 위치의 비인가 기능 키워드 및 타인 구역 차단)
  const pathParts = decodedPath.split('/').filter(Boolean);
  const notesIdx = pathParts.findIndex(p => p === 'notes');

  if (notesIdx !== -1 && pathParts.length > notesIdx + 1) {
    const rawTarget = pathParts.slice(notesIdx + 1).join('/');
    const lowerTarget = rawTarget.toLowerCase();

    // 4-1. export, admin 등 기능 경로 차단
    if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].some(k => lowerTarget.includes(k))) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 4-2. 강사 공지 단건 쓰기 재확인
    if ((lowerTarget.includes('instructor-announcement') || lowerTarget.startsWith('notice')) && isWriteMethod) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'zone_access_denied',
        ruleIds: ['zone_access_control'],
      };
    }

    // 4-3. 타인 메모 구역 식별 (other-learner 등 타 구역 자원 접근 거부)
    if (lowerTarget.includes('other') || lowerTarget.includes('victim')) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'zone_access_denied',
        ruleIds: ['zone_access_control'],
      };
    }
  }

  // 5. 접속 신호 점검 (7단계 복합 이상 접속)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 6. 야간 + 비정상 네트워크 + 대량 읽기 처리 (Step-up)
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

  // 7. 기타 이상 징후 처리
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

  // 8. 검증된 정상 단건 자원 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}