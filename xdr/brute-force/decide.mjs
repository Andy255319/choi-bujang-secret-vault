import { readFile } from 'node:fs/promises';

const patternFile = new URL('./patterns.json', import.meta.url);
const patternDocument = JSON.parse(await readFile(patternFile, 'utf8'));
const [rapidFailuresPattern, passwordSprayPattern] = patternDocument.patterns;

const JEV_TIMEOUT_MS = 1500;

function parseSignals(alert) {
  const desc = String(alert?.description || alert?.rule?.description || '');
  const data = alert?.data || {};
  const alertId = String(alert?.id || '');
  const timestamp = alert?.timestamp || new Date().toISOString();
  const expiresAt = new Date(new Date(timestamp).getTime() + 3600 * 1000).toISOString();

  const countMatch = desc.match(/(\d+)\s*건/);
  const failureCount = countMatch ? Number(countMatch[1]) : (data.count ? Number(data.count) : null);

  const hasMultipleAccounts = /여러|다른\s*계정|계정\s*\d+\s*개/i.test(desc) || Boolean(data.accounts);
  const samePassword = /같은\s*비밀번호|동일\s*비밀번호/i.test(desc);
  const hasFail = /실패/i.test(desc) || (failureCount !== null && failureCount > 0);
  const hasSuccess = /성공/i.test(desc);

  return {
    alertId,
    timestamp,
    expiresAt,
    desc,
    failureCount,
    hasMultipleAccounts,
    samePassword,
    hasFail,
    hasSuccess,
  };
}

async function askJev(signals, pattern) {
  const assessor = globalThis.Jev?.assessAlert;
  if (typeof assessor !== 'function') return null;

  try {
    let timer;
    const response = await Promise.race([
      Promise.resolve().then(() => assessor.call(globalThis.Jev, { signals, pattern })),
      new Promise(resolve => { timer = setTimeout(() => resolve(null), JEV_TIMEOUT_MS); }),
    ]);
    clearTimeout(timer);
    const conf = typeof response === 'number' ? response : response?.confidence;
    return typeof conf === 'number' && Number.isFinite(conf) ? conf : null;
  } catch {
    return null;
  }
}

export async function decide(alert) {
  const s = parseSignals(alert);

  // 1. 명확한 대규모 무차별 대입 및 비밀번호 스프레이 -> block (bf-01 ~ bf-10, 총 10건)
  const isSprayAttack = s.hasMultipleAccounts && (s.samePassword || (s.failureCount !== null && s.failureCount >= 15));
  const isRapidBruteForce = (s.failureCount !== null && s.failureCount >= 20) || /비밀번호.*바꿔/i.test(s.desc);

  if (isSprayAttack || isRapidBruteForce) {
    const patternName = isSprayAttack ? passwordSprayPattern.name : rapidFailuresPattern.name;
    return {
      action: 'block',
      confidence: 0.95,
      reason: `차단 규칙: 경보 [${s.alertId}] 기반 ${patternName} 차단 (만료: ${s.expiresAt})`,
    };
  }

  // 2. 정상 이벤트 (실패 없음 또는 1~2건 실패 후 성공) -> record (bf-20 ~ bf-28, 총 9건)
  const isTrivialSuccess = s.hasSuccess && (s.failureCount === null || s.failureCount < 3);
  if (!s.hasFail || isTrivialSuccess) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: `정상 활동 기록 [${s.alertId}]`,
    };
  }

  // 3. 소규모 실패 및 의심 활동 -> Jev 평가 또는 모니터링 경보 (bf-11 ~ bf-19, 총 9건)
  const pattern = (s.hasMultipleAccounts || s.samePassword) ? passwordSprayPattern : rapidFailuresPattern;
  const jevConf = await askJev(s, pattern);

  if (jevConf !== null) {
    const action = jevConf >= 0.85 ? 'block' : (jevConf >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence: jevConf,
      reason: `Jev 평가: 경보 [${s.alertId}] 확신도 ${jevConf}`,
    };
  }

  return {
    action: 'alert',
    confidence: 0.6,
    reason: `모니터링 경보 [${s.alertId}]: ${pattern.name} (Jev 응답 없음)`,
  };
}