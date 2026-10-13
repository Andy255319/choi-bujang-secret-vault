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

  // 1. 미등록 기기 거부 (6단계 핵심)
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 알 수 없는 경로 거부 (8단계: :id 깊이에 export 같은 기능 경로 불허)
  const route = request?.route || `${request?.method} ${request?.path}`;
  if (!ALLOWED_ROUTES.has(request?.route)) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  // 8단계 경로 깊이 검증: /notes/:id에서 id 자리에 export 등 기능 경로가 오지 못하도록 차단
  const pathParts = (request?.path || '').split('/').filter(Boolean);
  if (pathParts[0] === 'notes' && pathParts.length === 2) {
    const rawId = pathParts[1];
    // export, import, batch 등 알려진 비인가 기능 키워드 거부
    if (['export', 'import', 'batch', 'admin'].includes(rawId.toLowerCase())) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 구역 확인: 강사 공지(instructor-announcement)를 수정/삭제하려는 일반 요청 차단
    const parsedResource = parseResourceId(decodeURIComponent(rawId));
    if (parsedResource?.type === 'instructor-announcement') {
      if (request?.method !== 'GET') {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'instructor_zone_restricted',
          ruleIds: ['zone_access_control'],
        };
      }
    }
  }

  // 3. 접속 신호 점검 (7단계 복합 이상 접속 검사)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 4. 야간 + 비정상 네트워크 + 대량 읽기 처리 (Step-up)
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

  // 5. 기타 의심 신호 처리
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

  // 6. 정상 등록 기기 및 검증된 구역 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}