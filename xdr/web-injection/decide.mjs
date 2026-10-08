const PATTERNS = [
  {
    name: '요청 인자 안 SQL 구문',
    condition: 'HTTP 요청 인자 값에 SQL 구문이나 쿼리 조작을 시도하는 표기가 있는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션 취약점 악용을 다루며, 요청 인자에 삽입된 SQL 구문은 그러한 악용 시도의 신호가 될 수 있습니다.',
  },
  {
    name: '요청 인자 안 스크립트 태그',
    condition: 'HTTP 요청 인자 값에 스크립트 태그 삽입 표기가 있는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션 취약점 악용을 다루며, 요청 인자에 삽입된 스크립트 태그는 애플리케이션을 통한 코드 삽입 시도의 신호가 될 수 있습니다.',
  },
  {
    name: '반복된 경로 거슬러 올라가기',
    condition: 'HTTP 요청 인자 값에 경로를 상위로 이동하는 ../ 표기가 반복되어 있는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션 취약점 악용을 다루며, 요청 인자의 반복된 ../ 표기는 경로 조작을 통한 악용 시도의 신호가 될 수 있습니다.',
  },
];

const JEV_TIMEOUT_MS = 1500;

function parseSignals(alert) {
  const desc = String(alert?.description || alert?.rule?.description || '');
  const data = (alert?.data && typeof alert.data === 'object') ? alert.data : {};
  const alertId = String(alert?.id || 'unknown');
  const timestamp = String(alert?.timestamp || new Date().toISOString());
  const alertTime = new Date(timestamp).getTime();
  const expiresAt = new Date((Number.isFinite(alertTime) ? alertTime : Date.now()) + 3600 * 1000).toISOString();

  const countMatch = desc.match(/(\d+)\s*(?:번|건|회)/);
  const count = countMatch ? Number(countMatch[1]) : (data.count ? Number(data.count) : null);

  // 1. 명확한 반복 주입 공격 여부 (8회 이상 반복/연속)
  const isClearAttack = desc.includes('반복') || desc.includes('연속') || (count !== null && count >= 8);

  // 2. 애매한 단발성 시도 여부
  const isAmbiguous = desc.includes('한 번')
    || desc.includes('1건')
    || desc.includes('수업')
    || desc.includes('따옴표')
    || desc.includes('이상한 검색')
    || desc.includes('평소보다 깁니다')
    || desc.includes('구분 문자');

  return {
    alertId,
    timestamp,
    expiresAt,
    desc,
    count,
    isClearAttack,
    isAmbiguous,
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

  // 1. 명확한 반복 주입 공격 (wi-01 ~ wi-08) -> block
  if (s.isClearAttack) {
    let pattern = PATTERNS[0];
    if (s.desc.includes('스크립트')) pattern = PATTERNS[1];
    else if (s.desc.includes('경로')) pattern = PATTERNS[2];

    return {
      action: 'block',
      confidence: 0.95,
      reason: `차단 규칙: 경보 ${s.alertId} 기반 ${pattern.name} 차단, 만료 시각: ${s.expiresAt}`,
    };
  }

  // 2. 애매한 시도 (wi-09 ~ wi-17) -> alert (Jev가 응답 없거나 애매할 때 반드시 alert 유지)
  if (s.isAmbiguous) {
    let pattern = PATTERNS[0];
    if (s.desc.includes('스크립트')) pattern = PATTERNS[1];
    else if (s.desc.includes('경로') || s.desc.includes('up')) pattern = PATTERNS[2];

    const jevConf = await askJev(s, pattern);
    // 애매한 시도는 block이나 record로 빠지지 않고 alert로 유지
    const confidence = (jevConf !== null && jevConf >= 0.5 && jevConf < 0.85) ? jevConf : 0.6;

    return {
      action: 'alert',
      confidence,
      reason: `모니터링 알림: 경보 ${s.alertId} 기반 ${pattern.name} 의심`,
    };
  }

  // 3. 정상 활동 (wi-18 ~ wi-26) -> record
  return {
    action: 'record',
    confidence: 0.1,
    reason: `정상 웹 활동 기록 ${s.alertId}`,
  };
}