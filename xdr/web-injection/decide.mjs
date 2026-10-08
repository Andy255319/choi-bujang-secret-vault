import { readFile } from 'node:fs/promises';

const JEV_TIMEOUT_MS = 1500;
const patternsPromise = readFile(new URL('./patterns.json', import.meta.url), 'utf8')
  .then((contents) => {
    const parsed = JSON.parse(contents);
    if (!Array.isArray(parsed?.patterns)) throw new Error('웹 주입 패턴 형식이 아닙니다.');
    return parsed.patterns;
  });

function oneLine(value) {
  return String(value ?? '').replace(/[\r\n]+/g, ' ').trim();
}

function getDescription(alert) {
  return String(alert?.description ?? alert?.rule?.description ?? '');
}

function getRequestText(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const candidates = [
    data.url,
    data.uri,
    data.request,
    data.request_uri,
    data.query,
    data.params,
    data.requestBody,
    alert?.url,
    alert?.request,
  ];
  return candidates
    .filter((value) => typeof value === 'string')
    .join('\n');
}

function decodedOnce(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function getCount(alert, description) {
  const countMatch = description.match(/(\d+)\s*(?:번|회|건)/);
  if (countMatch) return Number(countMatch[1]);
  const dataCount = Number(alert?.data?.count);
  return Number.isFinite(dataCount) && dataCount > 0 ? dataCount : null;
}

function getPattern(patterns, kind) {
  const matchers = {
    sql: /sql/i,
    script: /스크립트|script/i,
    traversal: /경로|거슬러/i,
  };
  return patterns.find((pattern) => matchers[kind].test(String(pattern?.name ?? '')));
}

function findSignals(alert, patterns) {
  const description = getDescription(alert);
  const requestText = getRequestText(alert);
  const corpus = `${description}\n${requestText}\n${decodedOnce(requestText)}`;
  const count = getCount(alert, description);
  const repeatedInDescription = /반복|연속|번갈아|들어왔|나왔/.test(description)
    && (count ?? 0) >= 5;

  const sqlPattern = getPattern(patterns, 'sql');
  const scriptPattern = getPattern(patterns, 'script');
  const traversalPattern = getPattern(patterns, 'traversal');

  const sqlInDescription = /(?:sql\s*(?:구문|표기|표식)|데이터베이스\s*조회.*이어\s*붙)/i.test(description);
  const sqlPayload = /\bunion\b[\s\S]{0,80}\bselect\b/i.test(requestText)
    || /(?:['"]|%27|%22)\s*(?:or|and)\s+(?:['"][^'"]*['"]|\d+)\s*=\s*(?:['"][^'"]*['"]|\d+)/i.test(corpus);
  const hasSqlSignal = sqlInDescription || sqlPayload;

  const scriptInDescription = /스크립트\s*(?:삽입|표식)|<\s*script\b/i.test(description);
  const hasScriptTag = /<\s*script\b/i.test(corpus);
  const hasScriptSignal = scriptInDescription || hasScriptTag;

  const traversalInDescription = /경로.*(?:거슬러\s*올라가|이탈).*표기/i.test(description);
  const traversalMatches = [...corpus.matchAll(/\.\.\/(?:|%2f)|%2e%2e(?:%2f|\/)/ig)].length;
  const hasRepeatedTraversal = traversalMatches >= 2;
  const hasTraversalSignal = traversalInDescription || /\.\.\//i.test(corpus);

  const clearPatterns = [];
  if (sqlPattern && sqlPayload) clearPatterns.push(sqlPattern);
  else if (sqlPattern && sqlInDescription && repeatedInDescription) clearPatterns.push(sqlPattern);
  if (scriptPattern && hasScriptTag) clearPatterns.push(scriptPattern);
  else if (scriptPattern && scriptInDescription && repeatedInDescription) clearPatterns.push(scriptPattern);
  if (traversalPattern && hasRepeatedTraversal) clearPatterns.push(traversalPattern);
  else if (traversalPattern && traversalInDescription && repeatedInDescription) clearPatterns.push(traversalPattern);

  const candidates = [];
  if (hasSqlSignal && sqlPattern) candidates.push(sqlPattern);
  if (hasScriptSignal && scriptPattern) candidates.push(scriptPattern);
  if (hasTraversalSignal && traversalPattern) candidates.push(traversalPattern);

  const ruleLevel = Number(alert?.ruleLevel ?? alert?.rule?.level);
  const mitre = alert?.rule?.mitre;
  const hasT1190 = Array.isArray(mitre) && mitre.includes('T1190');
  const ambiguous = clearPatterns.length === 0
    && (hasT1190 && Number.isFinite(ruleLevel) && ruleLevel >= 5
      || candidates.length > 0
      || Number.isFinite(ruleLevel) && ruleLevel >= 8 && /공격|주입|이탈|구분\s*문자/i.test(description));

  return {
    clearPatterns,
    candidates,
    ambiguous,
    alertId: oneLine(alert?.id || 'unknown'),
    ruleLevel: Number.isFinite(ruleLevel) ? ruleLevel : null,
    hasT1190,
    count,
    indicators: {
      sql: hasSqlSignal,
      scriptTag: hasScriptSignal,
      repeatedTraversal: hasRepeatedTraversal || traversalInDescription && repeatedInDescription,
    },
  };
}

async function askJev(signals) {
  const assessor = globalThis.Jev?.assessAlert;
  if (typeof assessor !== 'function') return null;

  const candidateNames = signals.candidates.map((pattern) => oneLine(pattern.name));
  const pattern = {
    name: candidateNames.length > 0
      ? candidateNames.join(', ')
      : '미확정 (제공 패턴과 일치하는 신호 없음)',
  };
  const jevSignals = {
    alertId: signals.alertId,
    ruleLevel: signals.ruleLevel,
    mitreT1190: signals.hasT1190,
    repetitionCount: signals.count,
    indicators: signals.indicators,
  };

  let timer;
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => assessor.call(globalThis.Jev, { signals: jevSignals, pattern })),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), JEV_TIMEOUT_MS);
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
    clearTimeout(timer);
  }
}

/** 경보를 제공된 웹 주입 패턴과 대조해 판단합니다. */
export async function decide(alert) {
  const patterns = await patternsPromise;
  const signals = findSignals(alert, patterns);

  if (signals.clearPatterns.length > 0) {
    const names = signals.clearPatterns.map((pattern) => oneLine(pattern.name)).join(', ');
    return {
      action: 'block',
      confidence: 0.95,
      reason: names,
    };
  }

  if (!signals.ambiguous) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '일치하는 근거 패턴 없음 — 정상 이벤트로 기록',
    };
  }

  const confidence = await askJev(signals);
  const patternNames = signals.candidates.map((pattern) => oneLine(pattern.name));
  const reason = patternNames.length > 0
    ? patternNames.join(', ')
    : '미확정 (제공 패턴과 일치하는 신호 없음)';

  if (confidence === null) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason,
    };
  }

  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}
