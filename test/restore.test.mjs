import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyBackupIntegrity, computeContentHash, loadBackupNote } from '../src/restore-memo.mjs';
import { getPolicyDiff, restorePolicy, SAFE_POLICY_BACKUP } from '../src/policy-restore.mjs';

// 시험 계정 B의 가상 식별자
const TEST_ACCOUNT_B_ID = '00000000-0000-4000-8000-00000000000b';
const TEST_ACCOUNT_A_ID = '00000000-0000-4000-8000-00000000000a';

// 비공개 가상 메모 사본 원본 (시험 계정 B의 단 1건 메모)
const sampleContentB = '시험 계정 B의 3차 침공 전 검증된 비공개 가상 메모 본문입니다.';
const sampleHashB = computeContentHash(sampleContentB);

const backupSampleB = Object.freeze({
  id: '00000000-0000-4000-8000-00000000000b',
  owner_id: TEST_ACCOUNT_B_ID,
  title: '시험 계정 B 업무 일지 사본',
  content: sampleContentB,
  contentHash: sampleHashB,
  version: 'backup_v1',
});

test('사본 파일에서 시험 계정 B의 사본을 다시 읽어올 수 있다', () => {
  const loaded = loadBackupNote(TEST_ACCOUNT_B_ID);
  assert.ok(loaded);
  assert.equal(loaded.owner_id, TEST_ACCOUNT_B_ID);
  assert.equal(loaded.contentHash, sampleHashB);
});

test('사본이 존재하지 않으면 복원 검증이 즉시 중단된다', () => {
  const result = verifyBackupIntegrity({ id: 'non-existent' }, null, TEST_ACCOUNT_B_ID);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'backup_not_found');
});

test('시험 계정 B의 사본과 ID·소유자·내용 해시가 모두 일치하면 복원 검증에 성공한다', () => {
  const candidate = {
    id: backupSampleB.id,
    owner_id: TEST_ACCOUNT_B_ID,
    title: backupSampleB.title,
    content: sampleContentB,
    contentHash: sampleHashB,
  };

  const result = verifyBackupIntegrity(candidate, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(result.valid, true);
  assert.equal(result.verifiedId, backupSampleB.id);
  assert.equal(result.ownerId, TEST_ACCOUNT_B_ID);
  assert.equal(result.contentHash, sampleHashB);
  assert.equal(result.version, 'backup_v1');
});

test('내용 해시가 사본과 다르면(변조된 경우) 복원이 거부된다', () => {
  const tamperedCandidate = {
    id: backupSampleB.id,
    owner_id: TEST_ACCOUNT_B_ID,
    title: backupSampleB.title,
    content: '변조된 악성 내용',
    contentHash: sampleHashB, // 사본 해시와 불일치
  };

  const result = verifyBackupIntegrity(tamperedCandidate, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(result.valid, false);
  assert.match(result.reason, /content_hash/u);
});

test('소유자(owner_id)가 사본과 다르거나 타인 계정(A)이면 복원이 거부된다', () => {
  const wrongOwnerCandidate = {
    id: backupSampleB.id,
    owner_id: TEST_ACCOUNT_A_ID,
    title: backupSampleB.title,
    content: sampleContentB,
    contentHash: sampleHashB,
  };

  const result = verifyBackupIntegrity(wrongOwnerCandidate, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(result.valid, false);
  assert.match(result.reason, /owner/u);
});

test('자원 ID가 사본과 다르거나 메모 형식이 아니면 복원이 거부된다', () => {
  const wrongIdCandidate = {
    id: 'instructor-announcement:notice-999',
    owner_id: TEST_ACCOUNT_B_ID,
    title: backupSampleB.title,
    content: sampleContentB,
    contentHash: sampleHashB,
  };

  const result = verifyBackupIntegrity(wrongIdCandidate, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(result.valid, false);
  assert.match(result.reason, /memo_resource_id|id_mismatch/u);
});

test('안전 정책 사본 차이 계산 및 복원 검증이 정상 동작한다', () => {
  const currentAlteredRules = ['device_registered', 'step_up_required'];
  const diff = getPolicyDiff(currentAlteredRules, SAFE_POLICY_BACKUP);

  assert.equal(diff.verified, true);
  assert.equal(diff.targetVersion, 'safe_policy_v1');
  assert.equal(diff.hasDiff, true);
  assert.deepEqual(diff.changes.rulesToRestore, ['unusual_bulk_read_step_up', 'zone_access_control']);

  const restored = restorePolicy(currentAlteredRules, SAFE_POLICY_BACKUP);
  assert.equal(restored.success, true);
  assert.deepEqual(restored.restoredRules, SAFE_POLICY_BACKUP.rules);
});
