import { appendFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide as decideAlert } from './decide.mjs';
import { decide as baseDecide } from '../../src/decider.mjs';

const ALERTS_LOG_URL = new URL('../alerts.log', import.meta.url);
const FIXTURE_URL = new URL('../fixtures/persistence.json', import.meta.url);

/** 동적으로 등록된 ZTNA 거부 규칙 목록 */
export const dynamicBlockRules = [];

/**
 * decide 결과 가운데 차단 후보(block)만 ZTNA 판정기의 거부 규칙으로 등록합니다.
 * 정상 사용자를 막는 규칙은 등록하지 않습니다.
 */
export function addBlockRule(alert, decision) {
  // 정상 사용자 및 block이 아닌 경보는 규칙으로 등록하지 않음
  if (!decision || decision.action !== 'block') {
    return null;
  }

  const alertTime = alert.timestamp ? new Date(alert.timestamp).getTime() : Date.now();
  const expiresAt = new Date((Number.isFinite(alertTime) ? alertTime : Date.now()) + 3600 * 1000).toISOString();
  const alertId = alert.id || 'unknown';

  const rule = {
    id: `xdr_block_${alertId}`,
    alertId,
    expiresAt,
    srcip: alert.data?.srcip ?? null,
    reason: `차단 규칙: 경보 ${alertId} 기반 ${decision.reason} 차단, 만료 시각: ${expiresAt}`,
    confidence: decision.confidence,
  };

  // 중복 등록 방지
  if (!dynamicBlockRules.some((r) => r.alertId === alertId)) {
    dynamicBlockRules.push(rule);
  }
  return rule;
}

/**
 * 애매한 시도(alert)는 xdr/alerts.log에 한 줄씩 기록합니다.
 */
export async function logAlert(alert, decision) {
  const timestamp = alert.timestamp || new Date().toISOString();
  const alertId = alert.id || 'unknown';
  const entry = {
    timestamp,
    alertId,
    action: 'alert',
    reason: `모니터링 알림: 경보 ${alertId} 기반 ${decision.reason} 의심`,
  };

  try {
    const existing = await readFile(ALERTS_LOG_URL, 'utf8');
    if (!existing.includes(`"alertId":"${alertId}"`)) {
      await appendFile(ALERTS_LOG_URL, `${JSON.stringify(entry)}\n`, 'utf8');
    }
  } catch {
    await appendFile(ALERTS_LOG_URL, `${JSON.stringify(entry)}\n`, 'utf8');
  }
  return entry;
}

/**
 * 경보 1건을 처리하여, 차단 후보는 판정기 거부 규칙으로 연결하고
 * 애매한 시도는 alerts.log에 기록하며, 정상 이벤트는 통과시킵니다.
 */
export async function respond(alert) {
  const decision = await decideAlert(alert);

  if (decision.action === 'block') {
    const rule = addBlockRule(alert, decision);
    return {
      alertId: alert.id,
      action: 'block',
      decision: 'deny',
      rule,
      reason: decision.reason,
    };
  }

  if (decision.action === 'alert') {
    const logged = await logAlert(alert, decision);
    return {
      alertId: alert.id,
      action: 'alert',
      decision: 'alert',
      logged,
      reason: decision.reason,
    };
  }

  // 정상 이벤트 (record)
  return {
    alertId: alert.id,
    action: 'record',
    decision: 'allow',
    reason: decision.reason,
  };
}

/**
 * 동적 거부 규칙이 연동된 ZTNA 판정기 함수
 * 기존 판정기(src/decider.mjs) 규칙을 훼손하지 않고 동적 차단 규칙을 우선 평가합니다.
 */
export async function decideWithDynamicRules(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
  };

  const reqIp = request?.signals?.sourceAddress
    || request?.signals?.srcip
    || request?.clientIp
    || request?.data?.srcip;

  const now = Date.now();
  for (const rule of dynamicBlockRules) {
    const isExpired = new Date(rule.expiresAt).getTime() <= now;
    if (!isExpired && rule.srcip && reqIp === rule.srcip) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }
  }

  return baseDecide(request);
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  try {
    const fixture = JSON.parse(await readFile(FIXTURE_URL, 'utf8'));
    console.log(`총 ${fixture.alerts.length}건 경보 처리 시작...`);

    const summary = { block: 0, alert: 0, record: 0 };
    for (const alert of fixture.alerts) {
      const res = await respond(alert);
      summary[res.action] += 1;
    }

    console.log(`처리 결과: 차단 ${summary.block}건, 알림 기록 ${summary.alert}건, 정상 기록 ${summary.record}건`);
    console.log(`등록된 거부 규칙 수: ${dynamicBlockRules.length}건`);
  } catch (error) {
    console.error('응답 모듈 실행 오류:', error);
    process.exitCode = 1;
  }
}
