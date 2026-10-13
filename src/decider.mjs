export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'xdr_brute_force_block',
]);

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
  };

  // 1. 미등록 기기 거부 (6단계 핵심: 등록 상태가 아니면 즉시 거부)
  if (request.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. 복합 이상 징후 처리 (Step-up 요구)
  const isSuspicious = request.signals?.network === 'unusual' || request.signals?.region === 'foreign';
  const hasRiskEvent = Array.isArray(request.recentEvents) && request.recentEvents.some(e => e.kind === 'risk_signal');

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

  // 3. 등록된 기기의 정상 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}