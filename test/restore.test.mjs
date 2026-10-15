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

test('메모 외 다른 서비스 규칙(감사, 알림 등)은 zone_access_control로 차단되지 않고 보존된다', async () => {
  const { decide } = await import('../src/decider.mjs');
  const auditServiceReq = {
    schema: 'aleph.decision.v1',
    requestId: 'audit-req-1',
    classId: 'c1',
    projectId: 'p1',
    subjectId: 'user-1',
    deviceId: '0123456789abcdef',
    service: 'audit',
    method: 'GET',
    path: '/audit/logs',
    route: 'GET /audit/logs',
    queryLength: 0,
    querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 12 },
  };

  const result = await decide(auditServiceReq);
  assert.notEqual(result.reasonCode, 'route_not_allowed', '다른 서비스 경로가 메모 구역 규칙에 의해 차단되면 안 됩니다');
  assert.equal(result.decision, 'allow');
});

test('배열 형태의 사본이나 변조된 내용이 전달된 경우 사본 검증에서 정확히 탐지 및 거부된다', async () => {
  const { extractBackupSource } = await import('../src/restore-memo.mjs');
  const bodyWithArray = {
    backup: [
      {
        id: backupSampleB.id,
        owner_id: TEST_ACCOUNT_B_ID,
        title: '변조된 제목',
        content: '변조된 본문',
        contentHash: 'bad_hash',
      },
    ],
  };

  const extracted = extractBackupSource(bodyWithArray, TEST_ACCOUNT_B_ID, TEST_ACCOUNT_B_ID);
  assert.ok(extracted);
  assert.equal(extracted.content, '변조된 본문');

  // 추출된 변조 사본을 신뢰할 수 있는 사본과 대조 시 거부 확인
  const verifyResult = verifyBackupIntegrity(extracted, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(verifyResult.valid, false);
  assert.match(verifyResult.reason, /content_hash/u);
});

test('GET /api/restore 사전 조회 요청은 decider의 zone_access_control에서 허용된다', async () => {
  const { decide } = await import('../src/decider.mjs');
  const previewReq = {
    schema: 'aleph.decision.v1',
    requestId: 'preview-req-1',
    classId: 'c1',
    projectId: 'p1',
    subjectId: TEST_ACCOUNT_B_ID,
    deviceId: '0123456789abcdef',
    service: 'notes',
    method: 'GET',
    path: '/api/restore',
    route: 'GET /api/restore',
    queryLength: 0,
    querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 12 },
  };

  const result = await decide(previewReq);
  assert.equal(result.decision, 'allow');
  assert.equal(result.reasonCode, 'approved');
});

test('대상 ID가 지정되지 않거나 사본이 없으면 복원 검증이 즉시 중단된다', () => {
  const missingTargetResult = verifyBackupIntegrity(null, backupSampleB, TEST_ACCOUNT_B_ID);
  assert.equal(missingTargetResult.valid, false);
  assert.equal(missingTargetResult.reason, 'missing_target');

  const emptyCandidateResult = verifyBackupIntegrity({}, null, TEST_ACCOUNT_B_ID);
  assert.equal(emptyCandidateResult.valid, false);
  assert.equal(emptyCandidateResult.reason, 'backup_not_found');
});

test('B의 A 자료 요청은 거부되고 A 정상 요청은 유지된다 (zone_access_control)', async () => {
  const { decide } = await import('../src/decider.mjs');
  const bRequestsAReq = {
    schema: 'aleph.decision.v1',
    requestId: 'b-to-a-req-1',
    classId: 'c1',
    projectId: 'p1',
    subjectId: TEST_ACCOUNT_B_ID,
    deviceId: '0123456789abcdef',
    service: 'notes',
    method: 'GET',
    path: `/api/notes/${TEST_ACCOUNT_A_ID}`,
    route: 'GET /api/notes/:id',
    queryLength: 0,
    querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 12 },
  };

  const bResult = await decide(bRequestsAReq);
  assert.equal(bResult.decision, 'deny');
  assert.equal(bResult.reasonCode, 'route_not_allowed');
  assert.deepEqual(bResult.ruleIds, ['zone_access_control']);

  const aNormalReq = {
    ...bRequestsAReq,
    requestId: 'a-normal-req-1',
    subjectId: TEST_ACCOUNT_A_ID,
  };
  const aResult = await decide(aNormalReq);
  assert.equal(aResult.decision, 'allow');
  assert.equal(aResult.reasonCode, 'approved');
});

