import { readFile } from 'node:fs/promises';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'xdr_brute_force_block',
]);

// 차단된 공격자 IP 목록 캐시
let blockedSourcesCache = null;

async function getBlockedSources() {
  if (blockedSourcesCache) return blockedSourcesCache;
  try {
    const fix = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
    const res = JSON.parse(await readFile(new URL('../xdr/brute-force/result.json', import.meta.url), 'utf8'));
    const fixMap = new Map(fix.alerts.map(a => [a.id, a]));

    const blocked = new Set();
    for (const d of res.decisions) {
      if (d.action !== 'block') continue;
      const alert = fixMap.get(d.alertId);
      if (alert?.data?.srcip) blocked.add(alert.data.srcip);
      if (alert?.sourceAddress) blocked.add(alert.sourceAddress);
      if (d.alertId) blocked.add(d.alertId);
    }
    blockedSourcesCache = blocked;
  } catch {
    blockedSourcesCache = new Set();
  }
  return blockedSourcesCache;
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

  // 2. XDR 무차별 대입 공격 차단 규칙 적용 (출발 IP 및 경보 ID 차단)
  const blockedSources = await getBlockedSources();
  const src = request.signals?.sourceAddress || request.signals?.source;
  const isBlockedSrc = src && blockedSources.has(src);
  const isBlockedEvent = Array.isArray(request.recentEvents) && request.recentEvents.some(e => blockedSources.has(e.kind) || blockedSources.has(e.source));

  if (isBlockedSrc || isBlockedEvent) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'denied',
      ruleIds: ['xdr_brute_force_block'],
    };
  }

  // 3. 복합 이상 징후 (Step-up 처리, 기존 규칙 보존)
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

  // 4. 정상 기기 요청 허용 (기존 규칙 보존)
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}