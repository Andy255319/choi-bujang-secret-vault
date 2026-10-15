export async function runAttackChecks(config) {
  // 1단계 테스트 러너 (test:r5 호환)
  if (config.step === 1) {
    let appUrl = null;
    try {
      appUrl = new URL(config.publicAppUrl);
    } catch {}

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

    return [{
      attackId: 'anonymous_note_read',
      expected: '비로그인 화면에서 가짜 메모를 확인',
      observed: anonResult.ok
        ? `비로그인 요청에서 공개 가짜 메모 확인 표시가 보임 (HTTP ${anonResult.status})`
        : `비로그인 요청에서 확인표시가 보이지 않음 (HTTP ${anonResult.status || '미실행'})`,
    }];
  }

  // 12단계 심판 점검: 요청을 보내지 않은 점검은 공식 심판 계약에 따라 observed를 not_run으로 명시합니다.
  return [
    {
      attackId: 'anonymous_note_read',
      expected: '비로그인 화면에서 가짜 메모를 확인',
      observed: 'not_run',
    },
    {
      attackId: 'unauthenticated_notes_read',
      expected: '비인증 메모 목록 조회 거부 (HTTP 401)',
      observed: 'not_run',
    },
    {
      attackId: 'cross_tenant_note_read',
      expected: '타인 소유 메모 임의 접근 차단 (HTTP 401/403/404)',
      observed: 'not_run',
    },
    {
      attackId: 'unregistered_device_access',
      expected: '가상 미등록 기기 요청 거부 (device_not_registered)',
      observed: 'not_run',
    },
    {
      attackId: 'registered_device_access',
      expected: '가상 등록 기기 정상 요청 허용 (approved)',
      observed: 'not_run',
    },
    {
      attackId: 'unusual_bulk_read_step_up',
      expected: '복합 이상 가상 사건 추가 확인 (step_up_required)',
      observed: 'not_run',
    },
    {
      attackId: 'step_up_follow_up_fixture',
      expected: '가상 확인 완료 표시가 있는 후속 요청 허용',
      observed: 'not_run',
    },
    {
      attackId: 'notice_resource_type_confusion',
      expected: '강사 공지 자원 ID를 메모 요청으로 해석 거부',
      observed: 'not_run',
    },
    {
      attackId: 'complex_suspicious_revocation_proposed',
      expected: '10분 안 121건 이상 폭주 탐지 및 권한 회수 제안 (propose_revocation)',
      observed: 'not_run',
    },
    {
      attackId: 'backup_unverified_tampered_restore_blocked',
      expected: '사본 무결성 대조 검증 및 변조·사본 부재 시 복원 중단',
      observed: 'not_run',
    },
    {
      attackId: 'policy_diff_and_version_preview_verified',
      expected: '실행 전 안전 정책 사본 버전과 바뀔 항목 확인',
      observed: 'not_run',
    },
    {
      attackId: 'pwa_device_approval_verification',
      expected: '설치형 웹앱 접속 시 기기 등록 여부에 따른 판정',
      observed: 'not_run',
    },
  ];
}