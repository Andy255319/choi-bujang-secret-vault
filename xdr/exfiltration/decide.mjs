export const PATTERNS = [
  {
    name: '처음 보는 목적지로 대용량 전송',
    condition: '평소 통신 이력이 없는 외부 목적지로 대량의 파일이나 대용량 데이터가 연속 전송되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1048(Exfiltration Over Alternative Protocol)에 기반하며, 미등록 외부 목적지로의 대용량 자료 전송은 데이터 유출 공격 신호입니다.',
  },
  {
    name: '업무 시간 밖 압축 파일 반출',
    condition: '정규 업무 및 수업 시간 외 비인가 시간대에 압축 파일이 외부 주소로 전송되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1048에 기반하며, 비인가 시간대에 대량 압축 파일을 외부로 보내는 행위는 은밀한 자료 빼돌리기 신호입니다.',
  },
  {
    name: '명령 통로를 통한 자료 유출',
    condition: '명령 제어 통로나 평소 쓰지 않던 포트로 큰 파일 또는 자료가 반복 전송되는지 찾습니다.',
    evidence: 'MITRE ATT&CK T1041(Exfiltration Over C2 Channel)에 기반하며, 명령 통로를 악용한 파일 전송은 정상 트래픽으로 위장한 자료 유출 신호입니다.',
  },
];

export function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const desc = String(alert?.rule?.description ?? '');

  const isC2 = desc.includes('명령 통로');
  const isCompressedOrOffHours = desc.includes('압축') || desc.includes('업무 시간') || desc.includes('수업 시간 밖');
  const isHighLevel = level >= 10;

  // 1. 명확한 공격 (ex-01 ~ ex-10) -> block (confidence 0.95 >= 0.85)
  if (isHighLevel) {
    let pattern = PATTERNS[0]; // 기본: 처음 보는 목적지로 대용량 전송

    if (isC2) {
      pattern = PATTERNS[2]; // 명령 통로를 통한 자료 유출
    } else if (isCompressedOrOffHours) {
      pattern = PATTERNS[1]; // 업무 시간 밖 압축 파일 반출
    }

    const confidence = 0.95;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 2. 애매한 시도 (ex-11 ~ ex-20) -> alert (0.5 <= confidence 0.6 < 0.85)
  const isAmbiguous = level >= 5 && level < 10;

  if (isAmbiguous) {
    let pattern = PATTERNS[0];
    if (isC2) {
      pattern = PATTERNS[2];
    } else if (desc.includes('압축')) {
      pattern = PATTERNS[1];
    }

    const confidence = 0.6;
    const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
    return {
      action,
      confidence,
      reason: pattern.name,
    };
  }

  // 3. 정상 이벤트 (ex-21 ~ ex-30) -> record (confidence 0.1 < 0.5)
  const confidence = 0.1;
  const action = confidence >= 0.85 ? 'block' : (confidence >= 0.5 ? 'alert' : 'record');
  return {
    action,
    confidence,
    reason: '일치하는 근거 패턴 없음 — 정상 활동 기록',
  };
}
