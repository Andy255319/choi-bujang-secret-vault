import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { parseMemoResourceId } from './resource-id.mjs';
import { verifyBackupIntegrity, computeContentHash } from './restore-memo.mjs';

export async function runAttackChecks(config) {
  const checks = [];

  if (config.step >= 6) {
    const { normal, suspicious } = fixtureRequests();

    const unregisteredReq = {
      ...normal,
      requestId: 'attack-check-unregistered-device',
      deviceRegistered: false,
    };
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

      const followUp = {
        ...suspicious,
        requestId: 'attack-check-step-up-follow-up',
        stepUp: { verified: true, authAgeSeconds: 60 },
      };
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

    if (config.step >= 8) {
      const noticeRejected = parseMemoResourceId('instructor-announcement:notice-1') === null;
      checks.push({
        attackId: 'notice_resource_type_confusion',
        expected: '강사 공지 자원 ID를 메모 요청으로 해석 거부',
        observed: noticeRejected
          ? '공지 타입 자원 ID가 메모 파서에서 정상 거부됨'
          : '공지 타입 자원 ID가 거부되지 않음',
      });
    }

    if (config.step >= 9) {
      const START = Date.UTC(2026, 9, 1, 0, 0, 0);
      const suspiciousBurst = Array.from({ length: 121 }, (_, index) => ({
        at: new Date(START + index * 1000).toISOString(),
        method: 'GET',
        identity: { sub: 'learner_fixture' },
      }));
      const detectResult = detect(suspiciousBurst);
      const isBurstProposed = detectResult?.action === 'propose_revocation'
        && detectResult?.reasonCode === 'burst_read'
        && detectResult?.subject === 'learner_fixture';
      checks.push({
        attackId: 'complex_suspicious_revocation_proposed',
        expected: '10분 안 121건 이상 폭주 탐지 및 권한 회수 제안 (propose_revocation)',
        observed: isBurstProposed
          ? '가상 폭주 사건에서 learner_fixture 회수 제안이 정상 생성됨'
          : `회수 제안 미생성 또는 형식 불일치 (action: ${detectResult?.action}, reasonCode: ${detectResult?.reasonCode})`,
      });
    }

    if (config.step >= 10) {
      const sampleContent = '시험 계정 B의 가상 메모 사본';
      const sampleHash = computeContentHash(sampleContent);
      const backupSample = {
        id: '00000000-0000-4000-8000-00000000000b',
        owner_id: '00000000-0000-4000-8000-00000000000b',
        title: '시험 계정 B 사본',
        content: sampleContent,
        contentHash: sampleHash,
      };
      const matchResult = verifyBackupIntegrity(backupSample, backupSample, backupSample.owner_id);
      const tamperedResult = verifyBackupIntegrity({ ...backupSample, contentHash: 'badhash' }, backupSample, backupSample.owner_id);
      const isRestoreVerified = matchResult.valid && !tamperedResult.valid;

      checks.push({
        attackId: 'backup_single_memo_restore_verified',
        expected: '시험 계정 B의 사본과 ID·소유자·내용 해시 대조 시 단건 복원 통과 및 변조 거부',
        observed: isRestoreVerified
          ? '시험 계정 B의 ID·소유자·내용 해시가 사본과 일치할 때 복원 검증 통과 및 변조 거부 확인'
          : '단건 사본 복원 검증 실패',
      });
    }

    return checks;
  }

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
      visible = data?.sampleMarker === config.sampleMarker
        && Array.isArray(data.notes) && data.notes.length > 0;
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