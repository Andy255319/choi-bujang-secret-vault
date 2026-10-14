import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyBackupIntegrity, computeContentHash } from '../src/restore-memo.mjs';

// 시험 계정 B의 가상 식별자
const TEST_ACCOUNT_B_ID = '00000000-0000-4000-8000-00000000000b';
const TEST_ACCOUNT_A_ID = '00000000-0000-4000-8000-00000000000a';

// 비공개 가상 메모 사본 원본 (시험 계정 B의 단 1건 메모)
const sampleContentB = '시험 계정 B의 3차 침공 전 검증된 비공개 가상 메모 본문입니다.';
const sampleHashB = computeContentHash(sampleContentB);

const backupSampleB = Object.freeze({
  id: '00000000-0000-4000-8000-000000000001',
  owner_id: TEST_ACCOUNT_B_ID,
  title: '시험 계정 B 업무 일지 사본',
  content: sampleContentB,
  contentHash: sampleHashB,
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
