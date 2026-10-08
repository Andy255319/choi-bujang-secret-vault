export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
]);

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
  };

  // 1. 미등록 기기 차단
  if (request.deviceRegistered === false) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 무차별 공격 및 이상 징후 탐지
  const hasRiskEvents = Array.isArray(request.recentEvents) && request.recentEvents.some(
    e => e.kind === 'risk_signal' || (e.count && e.count >= 5) || e.kind?.includes('fail')
  );
  const isSuspiciousSignal = request.signals?.network === 'unusual' || request.signals?.region === 'foreign';

  if (hasRiskEvents || isSuspiciousSignal) {
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

  // 3. 정상 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}