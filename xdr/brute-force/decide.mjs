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
  const hasLoginFailure = /실패|로그인 실패/i.test(description);
  const hasMultipleAccounts = /여러 계정|서로 다른 계정|다른 계정|계정\s*\d+\s*개/.test(description);
  const samePassword = /같은 비밀번호|동일 비밀번호/.test(description);

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
    shortWindow: (durationMinutes !== null && durationMinutes <= 3)
      || /짧은 시간/.test(description),
    successMentioned: /성공/.test(description),
    passwordVariation: /비밀번호를 한 글자씩 바꿔|비밀번호.*바꿔 넣/.test(description),
    passwordChangeFlow: /비밀번호 변경 화면/.test(description),
    irregularIntervals: /간격은 고르지|불규칙/.test(description),
    afterLockout: /잠금 뒤|잠금 이후/.test(description),
    accountVariation: /계정 이름을 바꿔|계정을 바꿔/.test(description),
    sameSourceMentioned: /같은 주소|한 주소/.test(description),
  };
}

function choosePattern(signals) {
  return signals.hasMultipleAccounts || signals.samePassword
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

  // 원본 경보의 계정명·설명 전문 등은 전달하지 않고, 필요한 분류 신호만 보냅니다.
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

/** 경보를 패턴으로 판정하고, 애매한 경우에만 선택적으로 Jev에게 확신도를 묻습니다. */
export async function decide(alert) {
  const signals = getAlertSignals(alert);
  const pattern = choosePattern(signals);
  const hasAccountSpreadAndSamePassword = signals.hasMultipleAccounts && signals.samePassword;

  if (signals.hasLoginFailure && hasAccountSpreadAndSamePassword) {
    return decisionForConfidence(0.98, `근거 패턴: ${passwordSprayPattern.name}`);
  }

  if (signals.hasLoginFailure
      && signals.sourceAddress
      && signals.shortWindow
      && signals.failureCount >= 20) {
    return decisionForConfidence(0.96, `근거 패턴: ${rapidFailuresPattern.name}`);
  }

  const needsReview = signals.hasLoginFailure
    && ((signals.failureCount !== null && signals.failureCount >= 3)
      || /연속|대입|반복|이어졌|쌓였|실패가/.test(signals.description));

  if (!needsReview) {
    return decisionForConfidence(
      0.1,
      `일치 패턴 없음 (참고: ${rapidFailuresPattern.name}; ${passwordSprayPattern.name})`,
    );
  }

  const confidence = await askJev(signals, pattern);
  if (confidence === null) {
    return decisionForConfidence(0.5, `근거 패턴: ${pattern.name} (Jev 응답 없음 또는 시간 초과)`);
  }
  return decisionForConfidence(confidence, `근거 패턴: ${pattern.name} (Jev 확신도)`);
}
