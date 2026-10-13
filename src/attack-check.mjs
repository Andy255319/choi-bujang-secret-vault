import { decide } from './decider.mjs';

export async function runAttackChecks(config) {
  const checks = [];

  // 6단계 (또는 그 이상 단계): 기기 등록 여부 점검
  if (config.step >= 6) {
    // 1. 미등록 기기 가상 공격 점검
    const unregisteredReq = {
      requestId: 'attack-check-unregistered-device',
      deviceRegistered: false,
      service: 'notes',
      method: 'GET',
      path: '/notes',
      route: 'GET /notes',
      signals: { source: 'none', region: 'unknown', network: 'unknown' },
      recentEvents: [],
    };
    const unregResult = await decide(unregisteredReq);
    const unregBlocked = unregResult.decision === 'deny' && unregResult.reasonCode === 'device_not_registered';

    checks.push({
      attackId: 'unregistered_device_access',
      expected: '미등록 기기 요청 거부 (device_not_registered)',
      observed: unregBlocked
        ? '미등록 기기 요청이 device_not_registered로 정상 거부됨'
        : `거부되지 않음 (decision: ${unregResult.decision}, reasonCode: ${unregResult.reasonCode})`,
    });

    // 2. 등록 기기 정상 요청 점검
    const registeredReq = {
      requestId: 'attack-check-registered-device',
      deviceRegistered: true,
      service: 'notes',
      method: 'GET',
      path: '/notes',
      route: 'GET /notes',
      signals: { source: 'none', region: 'unknown', network: 'unknown' },
      recentEvents: [],
    };
    const regResult = await decide(registeredReq);
    const regAllowed = regResult.decision === 'allow' && regResult.reasonCode === 'approved';

    checks.push({
      attackId: 'registered_device_access',
      expected: '등록 기기 요청 허용 (approved)',
      observed: regAllowed
        ? '등록 기기 요청이 approved로 정상 허용됨'
        : `허용되지 않음 (decision: ${regResult.decision}, reasonCode: ${regResult.reasonCode})`,
    });

    return checks;
  }

  // 1단계 기본 점검
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json에 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes) && data.notes.length > 0;
    } catch {
      // JSON 파싱 실패
    }
  }

  return [{
    attackId: 'anonymous_note_read',
    expected: '비로그인 화면에서 가짜 메모를 확인',
    observed: visible
      ? '비로그인 요청에서 공개 가짜 메모 확인 표시가 보임'
      : `비로그인 요청에서 확인표시가 보이지 않음 (HTTP ${response.status})`,
  }];
}