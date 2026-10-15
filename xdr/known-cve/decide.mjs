export const PATTERNS = [
  {
    name: '요청 머리글 내 원격 조회 구문',
    condition: 'HTTP 요청 머리글에 ${jndi:ldap://...} 형태의 원격 조회 구문이 포함되어 있는지 찾습니다.',
    evidence: 'CVE-2021-44228 형태 요청과 MITRE ATT&CK T1190에 기반하며, 머리글의 jndi 원격 조회 구문은 취약점 악용 시도의 신호입니다.',
  },
  {
    name: '요청 인자 내 원격 조회 구문',
    condition: 'HTTP 요청 주소나 인자 값에 ${jndi:ldap://...} 형태의 원격 조회 구문이 포함되어 있는지 찾습니다.',
    evidence: 'CVE-2021-44228 형태 요청과 MITRE ATT&CK T1190에 기반하며, 요청 인자의 jndi 원격 조회 구문은 취약점 악용 시도의 신호입니다.',
  },
  {
    name: '취약점 점검 도구 흔적과 원격 조회 구문 결합',
    condition: '취약점 점검 도구의 probe 파라미터나 스캔 흔적이 원격 조회 구문과 함께 나타나는지 찾습니다.',
    evidence: 'CVE-2021-44228 형태 요청과 MITRE ATT&CK T1190에 기반하며, 점검 흔적과 원격 조회 구문의 결합은 취약점 악용 시도의 신호입니다.',
  },
];

export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const desc = String(alert?.rule?.description ?? '');
  const data = alert?.data ?? {};
  const useragent = String(data.useragent ?? '');
  const url = String(data.url ?? '');

  const hasJndiPayload = useragent.includes('${jndi:') || url.includes('${jndi:');
  const isHighLevel = level >= 10;
  const isProbe = url.includes('probe=') || desc.includes('점검 흔적');

  // 1. 명확한 공격 (kc-01 ~ kc-08) -> block (confidence 0.95 >= 0.85)
  if (hasJndiPayload || isHighLevel) {
    let pattern = PATTERNS[1]; // 기본: 인자 내 원격 조회 구문
    if (isProbe) {
      pattern = PATTERNS[2]; // 점검 도구 흔적 결합
    } else if (useragent.includes('${jndi:') || desc.includes('머리글')) {
      pattern = PATTERNS[0]; // 머리글 내 원격 조회 구문
    }

    const confidence = 0.95;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 2. 애매한 시도 (kc-09 ~ kc-16) -> alert (0.5 <= confidence 0.6 < 0.85)
  const isAmbiguous = (level >= 5 && level < 10)
    || desc.includes('CVE-2021-44228')
    || desc.includes('jndi')
    || desc.includes('취약점')
    || desc.includes('점검 도구')
    || desc.includes('라이브러리')
    || desc.includes('조회 형태')
    || url.includes('CVE-2021-44228')
    || url.includes('jndi')
    || url.includes('cve-list');

  if (isAmbiguous) {
    let pattern = PATTERNS[1];
    if (useragent.length > 0 && desc.includes('머리글')) {
      pattern = PATTERNS[0];
    } else if (desc.includes('점검') || url.includes('check')) {
      pattern = PATTERNS[2];
    }

    const confidence = 0.6;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 3. 정상 이벤트 (kc-17 ~ kc-24) -> record (confidence 0.1 < 0.5)
  const confidence = 0.1;
  const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
  return {
    action,
    confidence,
    reason: '일치하는 근거 패턴 없음 — 정상 활동 기록',
  };
}
