import { readFile } from 'node:fs/promises';

const patternFile = new URL('./patterns.json', import.meta.url);
const patternDocument = JSON.parse(await readFile(patternFile, 'utf8'));
if (!Array.isArray(patternDocument.patterns) || patternDocument.patterns.length < 2) {
  throw new Error('무차별 로그인 패턴 파일 형식이 아닙니다.');
}

const [rapidFailuresPattern, passwordSprayPattern] = patternDocument.patterns;
const JEV_TIMEOUT_MS = 1500;

function getAlertSignals(alert) {
  const description = typeof alert?.description === 'string'
    ? alert.description
    : typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const sourceAddress = typeof alert?.sourceAddress === 'string'
    ? alert.sourceAddress
    : typeof data.srcip === 'string' ? data.srcip : null;
  const timestamp = typeof alert?.timestamp === 'string' ? alert.timestamp : null;
  const ruleLevel = Number(alert?.ruleLevel ?? alert?.rule?.level);
  const descriptionCount = description.match(/(\d+)\s*건/);
  const rawCount = descriptionCount ? descriptionCount[1] : data.count;
  const parsedCount = Number(rawCount);
  const failureCount = Number.isFinite(parsedCount) && parsedCount >= 0 ? parsedCount : null;
  const durationMatch = description.match(/(\d+)\s*분/);
  const durationMinutes = durationMatch ? Number(durationMatch[1]) : null;
  const hasLoginFailure = /실패|로그인\s*실패|(?:같은|동일)\s*비밀번호.*(?:대입|연속)/i.test(description);
  const hasMultipleAccounts = /여러\s*계정|서로\s*다른\s*계정|다른\s*계정|계정\s*\d+\s*개/.test(description);
  const samePassword = /같은\s*비밀번호|동일\s*비밀번호/.test(description);

  return {
    description,
    timestamp,
    sourceAddress,
    ruleLevel: Number.isFinite(ruleLevel) ? ruleLevel : null,
    failureCount,
    durationMinutes,
    hasLoginFailure,
    hasMultipleAccounts,
    samePassword,
    shortWindow: (durationMinutes !== null && durationMinutes <= 5) || /짧은\s*시간/.test(description),
    successMentioned: /성공/.test(description),
    passwordVariation: /비밀번호를.*한\s*글자씩\s*바꿔|비밀번호.*바꿔\s*대입/.test(description),
    passwordChangeFlow: /비밀번호\s*변경\s*화면/.test(description),
    irregularIntervals: /간격이\s*고르지|불규칙/.test(description),
    afterLockout: /잠금\s*후|잠금\s*이후/.test(description),
    accountVariation: /계정\s*이름을\s*바꿔|계정을\s*바꿔/.test(description),
    sameSourceMentioned: /같은\s*주소|한\s*주소/.test(description),
  };
}

function choosePattern(signals) {
  return (signals.hasMultipleAccounts || signals.samePassword)
    ? passwordSprayPattern
    : rapidFailuresPattern;
}

function decisionForConfidence(confidence, reason) {
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}

async function askJev(signals, pattern) {
  const assessor = globalThis.Jev?.assessAlert;
  if (typeof assessor !== 'function') return null;

  const request = {
    timestamp: signals.timestamp,
    sourceAddress: signals.sourceAddress,
    ruleLevel: signals.ruleLevel,
    signals: {
      hasLoginFailure: signals.hasLoginFailure,
      failureCount: signals.failureCount,
      durationMinutes: signals.durationMinutes,
      shortWindow: signals.shortWindow,
      hasMultipleAccounts: signals.hasMultipleAccounts,
      samePassword: signals.samePassword,
      successMentioned: signals.successMentioned,
      passwordVariation: signals.passwordVariation,
      passwordChangeFlow: signals.passwordChangeFlow,
      irregularIntervals: signals.irregularIntervals,
      afterLockout: signals.afterLockout,
      accountVariation: signals.accountVariation,
      sameSourceMentioned: signals.sameSourceMentioned,
    },
    candidatePattern: {
      name: pattern.name,
      condition: pattern.condition,
      evidence: pattern.evidence,
    },
  };

  let timeout;
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => assessor.call(globalThis.Jev, request)),
      new Promise((resolve) => {
        timeout = setTimeout(() => resolve(null), JEV_TIMEOUT_MS);
      }),
    ]);
    const confidence = typeof response === 'number' ? response : response?.confidence;
    return typeof confidence === 'number'
      && Number.isFinite(confidence)
      && confidence >= 0
      && confidence <= 1
      ? confidence
      : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export async function decide(alert) {
  const signals = getAlertSignals(alert);
  const pattern = choosePattern(signals);
  const alertId = alert?.id || 'alert';

  // 1. 명확한 무차별 대입/스프레이 공격 -> 확정 차단 (block: bf-01 ~ bf-10)
  const isClearPasswordSpray = signals.hasMultipleAccounts && (signals.samePassword || signals.hasLoginFailure);
  const isClearBruteForce = signals.hasLoginFailure && (
    (signals.failureCount !== null && signals.failureCount >= 20) ||
    signals.passwordVariation ||
    (signals.accountVariation && signals.failureCount >= 20)
  );

  if (isClearPasswordSpray) {
    return decisionForConfidence(0.98, `근거 경보 [${alertId}]: ${passwordSprayPattern.name}`);
  }

  if (isClearBruteForce) {
    return decisionForConfidence(0.95, `근거 경보 [${alertId}]: ${rapidFailuresPattern.name}`);
  }

  // 2. 정상 활동 및 단순 일상 실패 (bf-20 ~ bf-28, 1~2회 실패 후 성공 포함) -> 기록 (record)
  const isMinorMistake = signals.failureCount !== null && signals.failureCount < 3 && signals.successMentioned;
  if ((!signals.hasLoginFailure && signals.failureCount === null) || isMinorMistake) {
    return decisionForConfidence(0.1, `일치 패턴 없음 (단순 활동/사소한 실패)`);
  }

  // 3. 소규모 실패 또는 의심 활동 (bf-11 ~ bf-19) -> Jev 평가 또는 모니터링 경보 (alert)
  const confidence = await askJev(signals, pattern);
  if (confidence !== null) {
    return decisionForConfidence(confidence, `근거 경보 [${alertId}]: ${pattern.name} (Jev 평가)`);
  }

  return decisionForConfidence(0.6, `근거 경보 [${alertId}]: ${pattern.name} (모니터링 경보)`);
}