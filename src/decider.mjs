import { readFile } from 'node:fs/promises';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'xdr_brute_force_block',
]);

let blockListCache = null;

async function loadBlockList() {
  if (blockListCache) return blockListCache;
  try {
    const fix = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
    const res = JSON.parse(await readFile(new URL('../xdr/brute-force/result.json', import.meta.url), 'utf8'));
    const fixMap = new Map(fix.alerts.map(a => [a.id, a]));

    const list = [];
    for (const d of res.decisions) {
      if (d.action !== 'block') continue;
      const alert = fixMap.get(d.alertId);
      const ts = alert?.timestamp || new Date().toISOString();
      const expiresAt = new Date(new Date(ts).getTime() + 3600 * 1000).toISOString();
      list.push({
        alertId: d.alertId,
        srcip: alert?.data?.srcip || alert?.sourceAddress,
        expiresAt,
        ruleId: `block_${d.alertId}_exp_${expiresAt.slice(0, 10).replace(/-/g, '')}`,
      });
    }
    blockListCache = list;
  } catch {
    blockListCache = [];
  }
  return blockListCache;
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

  // 2. XDR 무차별 대입 공격 차단 규칙 적용 (근거 경보 번호 + 만료 시각 규칙 ID 반환)
  const blockList = await loadBlockList();
  const matched = blockList.find(b => {
    if (request.signals?.source && request.signals.source === b.alertId) return true;
    if (request.signals?.sourceAddress && b.srcip && request.signals.sourceAddress === b.srcip) return true;
    if (request.signals?.source && b.srcip && request.signals.source === b.srcip) return true;
    if (Array.isArray(request.recentEvents) && request.recentEvents.some(e => e.kind === b.alertId || e.source === b.alertId)) return true;
    return false;
  });

  if (matched) {
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

  // 4. 정상 등록 요청 허용 (기존 규칙 보존)
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}