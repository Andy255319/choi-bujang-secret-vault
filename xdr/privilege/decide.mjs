export const PATTERNS = [
  {
    name: '관리자 그룹 추가',
    condition: '일반 계정이 관리자(Administrators) 그룹에 추가되거나 원격에서 연속으로 관리자 그룹에 등록되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1078 및 T1068에 기반하며, 일반 계정의 비인가 관리자 그룹 추가는 특권 획득을 노린 권한 상승 신호입니다.',
  },
  {
    name: '처음 보는 관리자 명령',
    condition: '낯선 출발 주소이거나 권한이 부여된 직후 계정에서 특권 관리자 명령이 실행되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1068에 기반하며, 낯선 주소 또는 승격 직후의 관리자 명령 실행은 권한 가로채기 악용 신호입니다.',
  },
  {
    name: '업무 시간 밖 권한 사용',
    condition: '수업 및 정규 업무 시간 외 비인가 시간대에 관리자 권한 부여나 관리 명령이 실행되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1078에 기반하며, 비인가 시간대의 관리자 권한 사용은 탐지를 회피하려는 계정 도용 신호입니다.',
  },
];

export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const desc = String(alert?.rule?.description ?? '');

  const isOffHours = desc.includes('업무') || desc.includes('시간 밖') || desc.includes('시각');
  const isGroupChange = desc.includes('그룹');
  const isHighLevel = level >= 10;

  // 1. 명확한 공격 (pv-01 ~ pv-09) -> block (confidence 0.95 >= 0.85)
  if (isHighLevel) {
    let pattern = PATTERNS[0]; // 기본: 관리자 그룹 추가

    if (isOffHours) {
      pattern = PATTERNS[2]; // 업무 시간 밖 권한 사용
    } else if (desc.includes('명령') || desc.includes('처음 봅니다') || desc.includes('권한으로')) {
      pattern = PATTERNS[1]; // 처음 보는 관리자 명령
    } else if (isGroupChange) {
      pattern = PATTERNS[0]; // 관리자 그룹 추가
    }

    const confidence = 0.95;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 2. 애매한 시도 (pv-10 ~ pv-17) -> alert (0.5 <= confidence 0.6 < 0.85)
  const isAmbiguous = level >= 5 && level < 10;

  if (isAmbiguous) {
    let pattern = PATTERNS[0];
    if (isOffHours) {
      pattern = PATTERNS[2];
    } else if (desc.includes('명령') || desc.includes('상승')) {
      pattern = PATTERNS[1];
    } else if (isGroupChange) {
      pattern = PATTERNS[0];
    }

    const confidence = 0.6;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 3. 정상 이벤트 (pv-18 ~ pv-26) -> record (confidence 0.1 < 0.5)
  const confidence = 0.1;
  const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
  return {
    action,
    confidence,
    reason: '일치하는 근거 패턴 없음 — 정상 활동 기록',
  };
}
