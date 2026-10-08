import { readFile } from 'node:fs/promises';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'xdr_brute_force_blocked',
]);

let blockRulesCache = null;

async function loadBlockRules() {
  if (blockRulesCache) return blockRulesCache;
  try {
    const res = JSON.parse(await readFile(new URL('../xdr/brute-force/result.json', import.meta.url), 'utf8'));
    const fix = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
    const fixMap = new Map(fix.alerts.map(a => [a.id, a]));

    blockRulesCache = res.decisions
      .filter(d => d.action === 'block')
      .map(d => {
        const alert = fixMap.get(d.alertId);
        const alertTime = alert?.timestamp ? new Date(alert.timestamp).getTime() : Date.now();
        const expiresAt = new Date(alertTime + 3600 * 1000).toISOString();
        return {
          alertId: d.alertId,
          srcip: alert?.data?.srcip || alert?.sourceAddress,
          srcuser: alert?.data?.srcuser,
          expiresAt,
          reason: d.reason,
        };
      });
  } catch {
    blockRulesCache = [];
  }
  return blockRulesCache;
}

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

  // 2. XDR 무차별 공격 거부 규칙 적용 (만료 시각 및 경보 번호 추적)
  const blockRules = await loadBlockRules();
  const matchedRule = blockRules.find(r => {
    if (request.signals?.sourceAddress && r.srcip && request.signals.sourceAddress === r.srcip) return true;
    if (request.signals?.source === r.alertId) return true;
    if (request.subjectId && r.srcuser && request.subjectId.includes(r.srcuser)) return true;
    return false;
  });

  if (matchedRule) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'brute_force_blocked',
      ruleIds: ['xdr_brute_force_blocked'],
    };
  }

  // 3. 복합 이상 징후 처리 (Step-up)
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

  // 4. 정상 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}