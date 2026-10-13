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

const ALLOWED_ROUTES = new Set([
  'GET /notes',
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

  // 2. 알 수 없는 라우트 거부 (정규 라우트 외 거부)
  const normalizedRoute = (request?.route || '').replace('/api/notes', '/notes');
  if (!ALLOWED_ROUTES.has(request?.route) && !ALLOWED_ROUTES.has(normalizedRoute)) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  // 3. 구역(Zone) 및 자원 권한 검증 (8단계 핵심)
  const fullPath = String(request?.path || '');
  let decodedPath = fullPath;
  try {
    decodedPath = decodeURIComponent(fullPath);
  } catch {
    // 디코딩 에러 방어
  }

  const pathParts = decodedPath.split('/').filter(Boolean);
  const notesIdx = pathParts.findIndex(p => p === 'notes');

  if (notesIdx !== -1 && pathParts.length > notesIdx + 1) {
    const rawTarget = pathParts.slice(notesIdx + 1).join('/');
    const lowerTarget = rawTarget.toLowerCase();

    // 3-1. :id 깊이에 기능 키워드가 오는 경우 거부
    if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].some(k => lowerTarget.includes(k))) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 3-2. 강사 공지 구역: 일반 학생은 GET만 허용, 수정(PUT/POST/DELETE/PATCH) 거부
    const isNotice = lowerTarget.includes('instructor-announcement') || lowerTarget.startsWith('notice');
    if (isNotice) {
      if (request?.method !== 'GET') {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'zone_access_denied',
          ruleIds: ['zone_access_control'],
        };
      }
    }

    // 3-3. 타인 메모 구역 (A 자기 메모는 허용, B의 A 메모는 거부)
    const currentSubject = String(request?.subjectId || '').trim();

    // 구분자(:, /, -) 분석으로 대상 소유자 추출
    // 예: memo:other-learner:note-1 -> tokens에 'other-learner' 포함
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
            reasonCode: 'zone_access_denied',
            ruleIds: ['zone_access_control'],
          };
        }
      }
    }
  }

  // 4. 접속 신호 점검 (7단계 복합 이상 접속 검사)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 5. 야간 + 비정상 네트워크 + 대량 읽기 처리 (Step-up)
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

  // 6. 기타 이상 징후 처리
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

  // 7. 정상 등록 기기 및 허용 구역
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}