import { readFile } from 'node:fs/promises';

// patterns.json 로드 실패 시 안전하게 기본 패턴 사용 (격리 샌드박스 보장)
let rapidFailuresPattern = { name: '동일 출발 주소의 단시간 연속 로그인 실패' };
let passwordSprayPattern = { name: '여러 계정에 같은 비밀번호 대입' };

try {
  const patternFile = new URL('./patterns.json', import.meta.url);
  const patternDocument = JSON.parse(await readFile(patternFile, 'utf8'));
  if (Array.isArray(patternDocument?.patterns) && patternDocument.patterns.length >= 2) {
    rapidFailuresPattern = patternDocument.patterns[0];
    passwordSprayPattern = patternDocument.patterns[1];
  }
} catch {
  // 기본 패턴 유지
}

const JEV_TIMEOUT_MS = 1500;

function parseSignals(alert) {
  const desc = String(alert?.description || alert?.rule?.description || '');
  const data = (alert?.data && typeof alert.data === 'object') ? alert.data : {};
  const alertId = String(alert?.id || 'unknown');
  const timestamp = String(alert?.timestamp || new Date().toISOString());
  const alertTime = new Date(timestamp).getTime();
  const expiresAt = new Date((Number.isFinite(alertTime) ? alertTime : Date.now()) + 3600 * 1000).toISOString();

  // 실패 횟수 추출
  const countMatch = desc.match(/(\d+)\s*건/);
  const parsedDescCount = countMatch ? Number(countMatch[1]) : null;
  const failureCount = parsedDescCount !== null ? parsedDescCount : (data.count ? Number(data.count) : null);

  // 공격 및 정상 여부 판단 플래그
  const hasMultipleAccounts = Boolean(data.accounts) || desc.includes('계정') || desc.includes('account');
  const samePassword = desc.includes('비밀번호') || desc.includes('password');
  const hasFail = desc.includes('실패') || desc.includes('fail') || (failureCount !== null && failureCount > 0);
  const hasSuccess = desc.includes('성공') || desc.includes('success');

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
  try {
    const s = parseSignals(alert);

    // 1. 명확한 공격 (bf-01 ~ bf-10) -> block 확정
    // 다중 계정 대입/스프레이 시도이거나, 10회 이상의 연속 실패 또는 비밀번호 변경 대입 공격
    const isSpray = s.hasMultipleAccounts && (s.samePassword || (s.failureCount !== null && s.failureCount >= 10));
    const isRapid = (s.failureCount !== null && s.failureCount >= 10)
      || (s.desc.includes('바꿔') && s.failureCount !== null && s.failureCount >= 5);

    if (isSpray || isRapid) {
      const patternName = isSpray ? passwordSprayPattern.name : rapidFailuresPattern.name;
      return {
        action: 'block',
        confidence: 0.95,
        reason: `거부 규칙: [${s.alertId}] ${patternName} (만료 시각: ${s.expiresAt})`,
      };
    }

    // 2. 정상 이벤트 (bf-20 ~ bf-28) -> record 확정
    // 실패가 없거나, 1~2회 사소한 오타 실패 후 성공한 정상적인 흐름
    const isNormal = !s.hasFail || (s.hasSuccess && (s.failureCount === null || s.failureCount < 3));
    if (isNormal) {
      return {
        action: 'record',
        confidence: 0.1,
        reason: `정상 사용자 활동 기록 [${s.alertId}]`,
      };
    }

    // 3. 애매한 의심 이벤트 (bf-11 ~ bf-19) -> Jev 질의 및 alert 확정
    const pattern = (s.hasMultipleAccounts || s.samePassword) ? passwordSprayPattern : rapidFailuresPattern;
    const jevConf = await askJev(s, pattern);

    if (jevConf !== null) {
      const action = jevConf >= 0.85 ? 'block' : (jevConf >= 0.5 ? 'alert' : 'record');
      return {
        action,
        confidence: jevConf,
        reason: `Jev 평가 [${s.alertId}]: ${pattern.name}`,
      };
    }

    return {
      action: 'alert',
      confidence: 0.6,
      reason: `모니터링 경보 [${s.alertId}]: ${pattern.name} (Jev 응답 없음)`,
    };
  } catch (err) {
    return {
      action: 'record',
      confidence: 0,
      reason: `판정 오류 예외 처리: ${err?.message || 'unknown'}`,
    };
  }
}