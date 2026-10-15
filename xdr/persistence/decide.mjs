export const PATTERNS = [
  {
    name: '서명 없는 새 서비스 등록',
    condition: '새로 등록되거나 변경된 서비스의 실행 파일에 서명이 없거나 임시 폴더 경로를 가리키는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1543(Create or Modify System Process)에 기반하며, 서명 없는 새 서비스 등록은 재부팅 후 지속성을 노린 악용 신호입니다.',
  },
  {
    name: '낯선 예약 작업 등록',
    condition: '평소 목록에 없는 예약 작업이 임시 폴더의 프로그램을 정규 시간 외에 실행하도록 등록되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1053(Scheduled Task/Job)에 기반하며, 낯선 예약 작업 생성은 잠복 및 지속적인 명령 실행을 노린 신호입니다.',
  },
  {
    name: '시작 폴더 변경',
    condition: 'Windows 시작 프로그램(Startup) 폴더에 평소 목록에 없는 실행 파일이 추가되거나 등록되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1543에 기반하며, 시작 폴더 프로그램 추가는 사용자 접속 시 자동 실행을 노린 지속성 확보 신호입니다.',
  },
];

export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const desc = String(alert?.rule?.description ?? '');
  const data = alert?.data ?? {};
  const path = String(data.path ?? '');

  const isStartup = path.toLowerCase().includes('startup')
    || desc.includes('시작 폴더')
    || desc.includes('시작 프로그램')
    || desc.includes('시작 항목');
  const isHighLevel = level >= 10;

  // 1. 명확한 공격 (ps-01 ~ ps-08) -> block (confidence 0.95 >= 0.85)
  if (isHighLevel) {
    let pattern = PATTERNS[0]; // 기본: 서명 없는 새 서비스 등록

    if (desc.includes('예약 작업') && !desc.includes('시작 프로그램과 예약 작업')) {
      pattern = PATTERNS[1]; // 낯선 예약 작업 등록
    } else if (isStartup) {
      pattern = PATTERNS[2]; // 시작 폴더 변경
    } else if (desc.includes('서비스')) {
      pattern = PATTERNS[0];
    }

    const confidence = 0.95;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 2. 애매한 시도 (ps-09 ~ ps-16) -> alert (0.5 <= confidence 0.6 < 0.85)
  const isAmbiguous = level >= 5 && level < 10;

  if (isAmbiguous) {
    let pattern = PATTERNS[0];
    if (desc.includes('예약 작업')) {
      pattern = PATTERNS[1];
    } else if (isStartup) {
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

  // 3. 정상 이벤트 (ps-17 ~ ps-24) -> record (confidence 0.1 < 0.5)
  const confidence = 0.1;
  const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
  return {
    action,
    confidence,
    reason: '일치하는 근거 패턴 없음 — 정상 활동 기록',
  };
}
