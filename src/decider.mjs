export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'unusual_bulk_read_step_up',
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

// Only the engine's explicitly tagged local fixture carries simulated context.
// Missing, unknown, or extra input is not converted into a normal connection.
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

  // 1. 미등록 기기 거부 (6단계 핵심: 등록 상태가 아니면 즉시 거부)
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 입력에 출처 표식·필수 접속/행동 정보가 없거나 계약 밖 필드가 있으면
  // 정상값으로 추정하지 않고 추가 확인을 요구합니다. 헤더는 접속 근거로 읽지 않습니다.
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 2. 야간(22:00~05:59) + 처음 보는 네트워크 + 최근 5분간 20회 이상 읽기면
  // 영구 차단하지 않고, 이유가 식별되는 규칙으로 추가 확인을 요구합니다.
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

  // 3. 다른 위험 신호는 기존처럼 추가 확인합니다. 지역만으로 영구 차단하지 않습니다.
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

  // 4. 등록된 기기의 정상 요청 허용 (judge_fixture는 가상 연습 신호에 한함)
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
