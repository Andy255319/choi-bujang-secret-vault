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

  // 2. 알 수 없는 경로 거부 (8단계 제작 2: 라우트 목록 확인)
  if (!ALLOWED_ROUTES.has(request?.route)) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  // 3. 구역(Zone) 및 자원 ID 정밀 검증 (8단계 핵심)
  const pathParts = (request?.path || '').split('/').filter(Boolean);
  if (pathParts[0] === 'notes' && pathParts.length === 2) {
    const rawId = pathParts[1];
    const decodedId = decodeURIComponent(rawId);

    // 3-1. :id 자리에 들어간 비인가 기능 경로 거부
    if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].includes(decodedId.toLowerCase())) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 3-2. 강사 공지 구역: 일반 학생은 읽기(GET)만 허용, 수정/삭제는 거부
    const parsedResource = parseResourceId(decodedId);
    if (parsedResource?.type === 'instructor-announcement' || decodedId.startsWith('instructor-announcement:')) {
      if (request?.method !== 'GET') {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'zone_access_denied',
          ruleIds: ['zone_access_control'],
        };
      }
    }

    // 3-3. 다른 사용자의 메모 구역 접근 거부 (B의 A 메모 조회/수정 차단)
    // 자원 ID가 소유자 정보를 포함하거나(콜론 또는 하이픈 분리), 다른 주체의 메모인 경우
    const subjectId = request?.subjectId;
    if (parsedResource?.type === 'memo') {
      const innerId = parsedResource.id;
      // 콜론으로 소유자와 메모ID가 나뉜 경우 (예: memo:<ownerId>:<noteId>)
      if (innerId.includes(':')) {
        const [owner] = innerId.split(':');
        if (owner && subjectId && owner !== subjectId) {
          return {
            ...base,
            decision: 'deny',
            reasonCode: 'zone_access_denied',
            ruleIds: ['zone_access_control'],
          };
        }
      }
    }

    // 일반 ID 형태에서도 타인 소유자 접두사나 불일치 패턴 식별
    if (decodedId.includes('@') || (decodedId.startsWith('user_') && subjectId && !decodedId.startsWith(subjectId))) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'zone_access_denied',
        ruleIds: ['zone_access_control'],
      };
    }
  }

  // 4. 접속 신호 점검 (7단계 복합 이상 접속)
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

  // 6. 기타 이상 징후
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

  // 7. 검증된 정상 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}