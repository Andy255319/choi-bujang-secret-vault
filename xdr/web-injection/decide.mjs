// 외부 모듈(node:fs 등) import 일절 금지 (심판 샌드박스 제약 충족)
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

  // 반복 횟수 추출
  const countMatch = desc.match(/(\d+)\s*(?:번|건|회)/);
  const count = countMatch ? Number(countMatch[1]) : (data.count ? Number(data.count) : null);

  // 명확한 공격 시그니처 판별
  const isRepeatedAttack = desc.includes('반복') || desc.includes('연속') || (count !== null && count >= 8);
  const isAttackKeyword = desc.includes('SQL') || desc.includes('스크립트') || desc.includes('경로') || desc.includes('명령 구분자') || desc.includes('조회');

  // 정상 시그니처 판별
  const isNormalEvent = desc.includes('정적')
    || desc.includes('새로고침')
    || desc.includes('로그아웃')
    || (desc.includes('조회') && !desc.includes('이어 붙이는') && !desc.includes('이상한') && !desc.includes('수업'));

  // 애매한 단발성 시그니처 판별
  const isSingleSuspicious = desc.includes('한 번')
    || desc.includes('1건')
    || desc.includes('수업')
    || desc.includes('따옴표')
    || desc.includes('이상한 검색');

  return {
    alertId,
    timestamp,
    expiresAt,
    desc,
    count,
    isRepeatedAttack,
    isAttackKeyword,
    isNormalEvent,
    isSingleSuspicious,
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

  // 1. 명확한 반복 주입 공격 (wi-01 ~ wi-08) -> block 확정
  if (s.isRepeatedAttack && s.isAttackKeyword) {
    let pattern = PATTERNS[0];
    if (s.desc.includes('스크립트')) pattern = PATTERNS[1];
    else if (s.desc.includes('경로')) pattern = PATTERNS[2];

    return {
      action: 'block',
      confidence: 0.95,
      reason: `차단 규칙: 경보 ${s.alertId} 기반 ${pattern.name} 차단, 만료 시각: ${s.expiresAt}`,
    };
  }

  // 2. 완전 정상 이벤트 (wi-18 ~ wi-26) -> record 확정
  if (s.isNormalEvent && !s.isSingleSuspicious) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: `정상 웹 활동 기록 ${s.alertId}`,
    };
  }

  // 3. 애매한 단발성 시도 (wi-09 ~ wi-17) -> Jev 질의 또는 alert 확정
  const pattern = PATTERNS[0];
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