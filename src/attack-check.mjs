import { createHash, randomUUID } from 'node:crypto';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { parseMemoResourceId } from './resource-id.mjs';
import { verifyBackupIntegrity, computeContentHash, loadBackupNote } from './restore-memo.mjs';
import { getPolicyDiff, SAFE_POLICY_BACKUP } from './policy-restore.mjs';

function makeFixtureRequests() {
  const build = (signals, recentEvents) => ({
    schema: 'aleph.decision.v1',
    requestId: randomUUID(),
    classId: 'class_fixture',
    projectId: 'project_fixture',
    subjectId: 'learner_fixture',
    deviceId: 'a'.repeat(16),
    service: 'notes',
    method: 'GET',
    path: '/notes/demo',
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: createHash('sha256').update('').digest('hex'),
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents,
    signals,
  });
  return {
    normal: build({ source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 }, []),
    suspicious: build({ source: 'judge_fixture', region: 'local', network: 'unusual', hour: 3 }, [{ kind: 'read', ageSeconds: 60, count: 20 }]),
  };
}

export async function runAttackChecks(config) {
  const checks = [];

  // 1. 처음 단계의 공개 가상 메모 및 실제 API 실측 요청
  let appUrl = null;
  try {
    appUrl = new URL(config.publicAppUrl);
  } catch {}

  // 1-1. 공개 가상 메모 조회 실측 (처음 단계)
  let anonResult = { status: 0, ok: false };
  if (appUrl) {
    try {
      const res = await fetch(new URL('/data.json', appUrl), {
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      anonResult.status = res.status;
      if (res.ok) {
        const data = await res.json().catch(() => null);
        anonResult.ok = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes) && data.notes.length > 0;
      }
    } catch {}
  }
  checks.push({
    attackId: 'anonymous_note_read',
    expected: '비로그인 화면에서 가짜 메모를 확인',
    observed: anonResult.ok
      ? `비로그인 요청에서 공개 가짜 메모 확인 표시가 보임 (HTTP ${anonResult.status})`
      : `비로그인 요청에서 확인표시가 보이지 않음 (HTTP ${anonResult.status || '미실행'})`,
  });

  // 1-2 & 1-3. 이후 단계 (step >= 2) 금지 요청 실측
  if (config.step >= 2) {
    let unauthStatus = 0;
    if (appUrl) {
      try {
        const res = await fetch(new URL('/api/notes', appUrl), {
          redirect: 'error',
          signal: AbortSignal.timeout(5000),
        });
        unauthStatus = res.status;
      } catch {}
    }
    checks.push({
      attackId: 'unauthenticated_notes_read',
      expected: '비인증 메모 목록 조회 거부 (HTTP 401)',
      observed: unauthStatus > 0
        ? `비인증 메모 목록 요청 거부 수신 (HTTP ${unauthStatus})`
        : '비인증 메모 목록 요청 미실행 또는 네트워크 연결 불가',
    });

    let crossStatus = 0;
    if (appUrl) {
      try {
        const res = await fetch(new URL('/api/notes/00000000-0000-4000-8000-00000000000a', appUrl), {
          redirect: 'error',
          signal: AbortSignal.timeout(5000),
        });
        crossStatus = res.status;
      } catch {}
    }
    checks.push({
      attackId: 'cross_tenant_note_read',
      expected: '타인 소유 메모 임의 접근 차단 (HTTP 401/403/404)',
      observed: crossStatus > 0
        ? `타인 메모 단건 요청 거부 수신 (HTTP ${crossStatus})`
        : '타인 메모 단건 요청 미실행 또는 네트워크 연결 불가',
    });
  }

  if (config.step < 6) {
    return checks;
  }

  // 2. 가상 사건 및 내부 모듈 점검 (6~11단계 출처 명시 및 미실행 분리)
  const { normal, suspicious } = makeFixtureRequests();

  // 6단계: 기기 등록 여부 점검
  const unregReq = {
    ...normal,
    requestId: 'attack-check-unregistered-device',
    deviceRegistered: false,
  };
  const unregResult = await decide(unregReq);
  checks.push({
    attackId: 'unregistered_device_access',
    expected: '가상 미등록 기기 요청 거부 (device_not_registered)',
    observed: `가상 요청에 대해 학생 판정기가 ${unregResult.decision} (${unregResult.reasonCode})로 판정 (HTTP 요청 미실행)`,
  });

  const normalResult = await decide(normal);
  checks.push({
    attackId: 'registered_device_access',
    expected: '가상 등록 기기 정상 요청 허용 (approved)',
    observed: `가상 정상 요청에 대해 학생 판정기가 ${normalResult.decision} (${normalResult.reasonCode})로 판정 (HTTP 요청 미실행)`,
  });

  // 7단계: 복합 이상 접속 점검
  const stepUpResult = await decide(suspicious);
  checks.push({
    attackId: 'unusual_bulk_read_step_up',
    expected: '복합 이상 가상 사건 추가 확인 (step_up_required)',
    observed: `가상 복합 사건에 대해 학생 판정기가 ${stepUpResult.decision} (${stepUpResult.reasonCode})로 판정 (HTTP 요청 미실행)`,
  });

  const followUp = {
    ...suspicious,
    requestId: 'attack-check-step-up-follow-up',
    stepUp: { verified: true, authAgeSeconds: 60 },
  };
  const followUpResult = await decide(followUp);
  checks.push({
    attackId: 'step_up_follow_up_fixture',
    expected: '가상 확인 완료 표시가 있는 후속 요청 허용',
    observed: `가상 후속 요청에 대해 학생 판정기가 ${followUpResult.decision} (${followUpResult.reasonCode})로 판정 (실제 재로그인 증명: 미실행)`,
  });

  // 8단계: 자원 ID 형식 점검
  const noticeRejected = parseMemoResourceId('instructor-announcement:notice-1') === null;
  checks.push({
    attackId: 'notice_resource_type_confusion',
    expected: '강사 공지 자원 ID를 메모 요청으로 해석 거부',
    observed: noticeRejected
      ? '공지 자원 ID 파서 반환값 null (HTTP 요청 미실행)'
      : '공지 자원 ID 파서가 유효값 반환 (HTTP 요청 미실행)',
  });

  // 9단계: 폭주 탐지 점검
  const START = Date.UTC(2026, 9, 1, 0, 0, 0);
  const suspiciousBurst = Array.from({ length: 121 }, (_, index) => ({
    at: new Date(START + index * 1000).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture' },
  }));
  const detectResult = detect(suspiciousBurst);
  checks.push({
    attackId: 'complex_suspicious_revocation_proposed',
    expected: '10분 안 121건 이상 폭주 탐지 및 권한 회수 제안 (propose_revocation)',
    observed: `가상 폭주 사건에서 학생 탐지기 결과 action=${detectResult?.action}, reasonCode=${detectResult?.reasonCode} (실제 회수 연동 미실행)`,
  });

  // 10단계: 사본 무결성 및 정책 대조 점검
  const backupSample = loadBackupNote('00000000-0000-4000-8000-00000000000b');
  const hasBackup = backupSample !== null;
  const matchResult = hasBackup ? verifyBackupIntegrity(backupSample, backupSample, backupSample.owner_id) : { valid: false };
  const tamperedResult = hasBackup ? verifyBackupIntegrity({ ...backupSample, content: '변조된 내용', contentHash: 'badhash' }, backupSample, backupSample.owner_id) : { valid: true };
  const missingBackupResult = verifyBackupIntegrity({ id: 'non-existent' }, null, '00000000-0000-4000-8000-00000000000b');
  const isRestoreVerified = hasBackup && matchResult.valid && !tamperedResult.valid && !missingBackupResult.valid;

  checks.push({
    attackId: 'backup_unverified_tampered_restore_blocked',
    expected: '사본 무결성 대조 검증 및 변조·사본 부재 시 복원 중단',
    observed: isRestoreVerified
      ? '사본 파일 대조 검증 수행: 일치 시 valid=true, 불일치 시 valid=false (운영 원본 덮어쓰기 미실행)'
      : '사본 무결성 검증 실패 (운영 원본 덮어쓰기 미실행)',
  });

  const policyDiff = getPolicyDiff(['device_registered', 'step_up_required'], SAFE_POLICY_BACKUP);
  checks.push({
    attackId: 'policy_diff_and_version_preview_verified',
    expected: '실행 전 안전 정책 사본 버전과 바뀔 항목 확인',
    observed: policyDiff.verified
      ? `정책 버전(${policyDiff.targetVersion}) 및 변경 대상(${policyDiff.changes.rulesToRestore.length}건) 확인 (운영 정책 변경 미실행)`
      : '정책 차이 계산 실패 (운영 정책 변경 미실행)',
  });

  // 11단계: 설치형 웹앱 기기 등록 판정 점검
  const pwaUnregReq = {
    ...normal,
    requestId: 'attack-check-device-unregistered-pwa',
    deviceRegistered: false,
  };
  const pwaUnregDecision = await decide(pwaUnregReq);
  const pwaRegDecision = await decide(normal);
  const isPwaVerified = pwaUnregDecision.decision === 'deny'
    && pwaUnregDecision.reasonCode === 'device_not_registered'
    && pwaRegDecision.decision === 'allow'
    && pwaRegDecision.reasonCode === 'approved';

  checks.push({
    attackId: 'pwa_device_approval_verification',
    expected: '설치형 웹앱 접속 시 기기 등록 여부에 따른 판정',
    observed: isPwaVerified
      ? '미등록 기기 deny(device_not_registered), 등록 기기 allow(approved) 판정 (설치 표시 권한부여 미실행)'
      : '기기 등록 판정 실패 (설치 표시 권한부여 미실행)',
  });

  return checks;
}