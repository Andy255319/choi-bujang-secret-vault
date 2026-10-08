import { readFile } from 'node:fs/promises';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'xdr_brute_force_blocked',
]);

let blockedAlertsCache = null;

async function getBlockedAlerts() {
  if (blockedAlertsCache) return blockedAlertsCache;
  try {
    const res = JSON.parse(await readFile(new URL('../xdr/brute-force/result.json', import.meta.url), 'utf8'));
    const fix = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
    const fixMap = new Map(fix.alerts.map(a => [a.id, a]));

    const map = new Map();
    for (const d of res.decisions) {
      if (d.action !== 'block') continue;
      const alert = fixMap.get(d.alertId);
      const ts = alert?.timestamp ? new Date(alert.timestamp).getTime() : Date.now();
      const expiresAt = new Date(ts + 3600 * 1000).toISOString();
      map.set(d.alertId, {
        alertId: d.alertId,
        expiresAt,
        ruleId: `xdr_${d.alertId}_exp_${expiresAt.replace(/[^0-9]/g, '').slice(0, 14)}`,
        reason: d.reason,
      });
    }
    blockedAlertsCache = map;
  } catch {
    blockedAlertsCache = new Map();
  }
  return blockedAlertsCache;
}

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
  };

  // 1. 미등록 기기 차단 (기존 규칙 보존)
  if (request.deviceRegistered === false) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. XDR 차단 후보 공격 요청 차단
  const blockedMap = await getBlockedAlerts();
  const matched = blockedMap.get(request.signals?.source)
    || (Array.isArray(request.recentEvents) && request.recentEvents.find(e => blockedMap.has(e.kind) || blockedMap.has(e.source)))
    || null;

  const targetAlert = matched?.alertId ? matched : (matched ? blockedMap.get(matched.kind || matched.source) : null);

  if (targetAlert) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'denied',
      ruleIds: [targetAlert.ruleId, 'xdr_brute_force_blocked'],
    };
  }

  // 3. 복합 이상 징후 (Step-up 처리)
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

  // 4. 정상 등록 기기 요청 허용
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}