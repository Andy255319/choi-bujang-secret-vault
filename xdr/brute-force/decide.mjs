const JEV_TIMEOUT_MS = 1500;

function parseSignals(alert) {
  const desc = String(alert?.description || alert?.rule?.description || '');
  const data = (alert?.data && typeof alert.data === 'object') ? alert.data : {};
  const alertId = String(alert?.id || 'unknown');
  const timestamp = String(alert?.timestamp || new Date().toISOString());
  const alertTime = new Date(timestamp).getTime();
  const expiresAt = new Date((Number.isFinite(alertTime) ? alertTime : Date.now()) + 3600 * 1000).toISOString();

  const countMatch = desc.match(/(\d+)\s*건/);
  const parsedDescCount = countMatch ? Number(countMatch[1]) : null;
  const failureCount = parsedDescCount !== null ? parsedDescCount : (data.count ? Number(data.count) : null);

  const hasMultipleAccounts = Boolean(data.accounts) || desc.includes('계정') || desc.includes('account');
  const samePassword = desc.includes('비밀번호') || desc.includes('password');
  const hasFail = desc.includes('실패') || desc.includes('fail') || (failureCount !== null && failureCount > 0);
  const hasSuccess = desc.includes('성공') || desc.includes('success');

  return {
    alertId,
    timestamp,
    expiresAt,
    desc,
    data,
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

  // 1. 명확한 공격 (bf-01 ~ bf-10) -> block 확정
  const isSpray = Boolean(s.data.accounts) || (s.hasMultipleAccounts && s.samePassword);
  const isRapid = (s.failureCount !== null && s.failureCount >= 15) || (s.desc.includes('바꿔') && s.failureCount !== null && s.failureCount >= 10);

  if (isSpray || isRapid) {
    const patternName = isSpray ? '여러 계정에 같은 비밀번호 대입' : '동일 출발 주소의 단시간 연속 로그인 실패';
    return {
      action: 'block',
      confidence: 0.95,
      reason: `차단 규칙: 경보 ${s.alertId} 기반 ${patternName} 차단, 만료 시각: ${s.expiresAt}`,
    };
  }

  // 2. 정상 활동 (bf-20 ~ bf-28) -> record 확정
  const isNormal = !s.hasFail || (s.hasSuccess && (s.failureCount === null || s.failureCount < 3));
  if (isNormal) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: `정상 활동 기록 ${s.alertId}`,
    };
  }

  // 3. 의심 활동 (bf-11 ~ bf-19) -> alert
  const pattern = { name: s.hasMultipleAccounts ? '비밀번호 스프레이 의심' : '단시간 로그인 실패 의심' };
  const jevConf = await askJev(s, pattern);

  if (jevConf !== null) {
    const action = jevConf >= 0.85 ? 'block' : (jevConf >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence: jevConf,
      reason: `Jev 평가 ${s.alertId}: 확신도 ${jevConf}`,
    };
  }

  return {
    action: 'alert',
    confidence: 0.6,
    reason: `모니터링 경보 ${s.alertId}: ${pattern.name} (Jev 응답 없음)`,
  };
}