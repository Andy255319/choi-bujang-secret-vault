import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from './decider.mjs';

export async function runAttackChecks(config) {
  const checks = [];

  // 6단계 이상은 엔진 실제 호출이 아닌 계약 모양의 로컬 가상 요청만 점검합니다.
  if (config.step >= 6) {
    const { normal, suspicious } = fixtureRequests();
    const unregisteredReq = { ...normal, requestId: 'attack-check-unregistered-device',
      deviceRegistered: false };
    const unregResult = await decide(unregisteredReq);
    const unregBlocked = unregResult.decision === 'deny'
      && unregResult.reasonCode === 'device_not_registered';
    checks.push({
      attackId: 'unregistered_device_access',
      expected: '가상 미등록 기기 요청 거부 (device_not_registered)',
      observed: unregBlocked
        ? '가상 요청이 device_not_registered로 거부됨'
        : `예상한 거부가 아님 (decision: ${unregResult.decision}, reasonCode: ${unregResult.reasonCode})`,
    });

    const normalResult = await decide(normal);
    const normalAllowed = normalResult.decision === 'allow'
      && normalResult.reasonCode === 'approved';
    checks.push({
      attackId: 'registered_device_access',
      expected: '가상 등록 기기 정상 요청 허용 (approved)',
      observed: normalAllowed
        ? '가상 정상 요청이 approved로 허용됨'
        : `예상한 허용이 아님 (decision: ${normalResult.decision}, reasonCode: ${normalResult.reasonCode})`,
    });

    if (config.step >= 7) {
      const stepUpResult = await decide(suspicious);
      const requiresStepUp = stepUpResult.decision === 'step_up'
        && stepUpResult.reasonCode === 'step_up_required'
        && stepUpResult.ruleIds.includes('unusual_bulk_read_step_up');
      checks.push({
        attackId: 'unusual_bulk_read_step_up',
        expected: '복합 이상 가상 사건 추가 확인 (step_up_required)',
        observed: requiresStepUp
          ? '가상 복합 사건이 unusual_bulk_read_step_up 규칙으로 추가 확인됨'
          : `예상한 추가 확인이 아님 (decision: ${stepUpResult.decision}, reasonCode: ${stepUpResult.reasonCode})`,
      });

      // This is only a simulated follow-up carrying the contract's verified flag.
      // It does not establish that a new login was completed for the same user.
      const followUp = { ...suspicious, requestId: 'attack-check-step-up-follow-up',
        stepUp: { verified: true, authAgeSeconds: 60 } };
      const followUpResult = await decide(followUp);
      const followUpAllowed = followUpResult.decision === 'allow'
        && followUpResult.reasonCode === 'approved';
      checks.push({
        attackId: 'step_up_follow_up_fixture',
        expected: '가상 확인 완료 표시가 있는 후속 요청 허용 (실제 재로그인 증명 아님)',
        observed: followUpAllowed
          ? '가상 확인 완료 표시로 후속 요청이 허용됨; 실제 재로그인 검증은 미실행'
          : `가상 후속 요청이 허용되지 않음 (decision: ${followUpResult.decision}, reasonCode: ${followUpResult.reasonCode}); 실제 재로그인 검증은 미실행`,
      });
    }
    return checks;
  }

  // 1단계 기본 점검: 실제 배포 공개 경로를 직접 요청합니다.
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
