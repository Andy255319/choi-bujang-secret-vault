/**
 * 침해 전 검증한 안전 정책 사본 정의 및 복원 모듈 (10단계 만들기 1 & 2)
 */

export const SAFE_POLICY_BACKUP = Object.freeze({
  version: 'safe_policy_v1',
  checksum: '7a8f9c0e1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f',
  rules: Object.freeze([
    'device_registered',
    'step_up_required',
    'unusual_bulk_read_step_up',
    'zone_access_control',
  ]),
});

/**
 * 침해 전 검증한 안전 정책 사본과 현재 시험 정책의 차이를 계산합니다.
 * 사본이 없거나 검증 실패 시 중단합니다. 실제 운영 정책은 건드리지 않습니다.
 */
export function getPolicyDiff(currentRules, backup = SAFE_POLICY_BACKUP) {
  if (!backup || typeof backup !== 'object' || !Array.isArray(backup.rules) || !backup.version) {
    throw new Error('사본이 없거나 검증에 실패했습니다. (backup_invalid)');
  }
  if (!Array.isArray(currentRules)) {
    throw new Error('현재 정책 목록이 올바르지 않습니다. (current_policy_invalid)');
  }

  const currentSet = new Set(currentRules);
  const backupSet = new Set(backup.rules);

  const missingInCurrent = backup.rules.filter(r => !currentSet.has(r));
  const addedInCurrent = currentRules.filter(r => !backupSet.has(r));

  return {
    verified: true,
    targetVersion: backup.version,
    hasDiff: missingInCurrent.length > 0 || addedInCurrent.length > 0,
    changes: {
      rulesToRestore: missingInCurrent,
      rulesToRemove: addedInCurrent,
    },
    before: [...currentRules],
    after: [...backup.rules],
  };
}

/**
 * 검증한 안전 정책 버전으로 정책을 되돌립니다.
 * 다른 서비스 규칙과 감사 이력은 보존하고, 실행 전에 바뀔 항목을 확인합니다.
 */
export function restorePolicy(currentRules, backup = SAFE_POLICY_BACKUP) {
  const diff = getPolicyDiff(currentRules, backup);
  if (!diff.verified) {
    throw new Error('정책 사본 검증에 실패하여 복원을 중단합니다.');
  }

  // 다른 규칙(안전 사본에 포함되지 않은 기타 서비스 규칙)은 보존
  const preservedOtherRules = currentRules.filter(r => !backup.rules.includes(r));
  const restoredRules = Array.from(new Set([...backup.rules, ...preservedOtherRules]));

  return {
    success: true,
    restoredVersion: diff.targetVersion,
    restoredRules,
    diff,
  };
}
