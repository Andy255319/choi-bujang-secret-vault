import crypto from 'node:crypto';
import { parseMemoResourceId, createResourceId } from './resource-id.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

/**
 * 메모 내용의 SHA-256 해시를 계산합니다.
 */
export function computeContentHash(content) {
  const text = typeof content === 'string' ? content : String(content ?? '');
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * 복구 대상 단건 사본의 ID·소유자·내용 해시를 원본 사본과 대조하여 검증합니다.
 * @param {object} target - 복원 대상 객체 ({ id, owner_id, content, contentHash })
 * @param {object} backupSample - 신뢰할 수 있는 비공개 사본 원본 객체
 * @param {string} verifiedUserId - 인증된 사용자 ID
 */
export function verifyBackupIntegrity(target, backupSample, verifiedUserId) {
  if (!target || typeof target !== 'object') {
    return { valid: false, reason: 'missing_target' };
  }
  if (!backupSample || typeof backupSample !== 'object') {
    return { valid: false, reason: 'missing_backup_source' };
  }

  // 1. ID 대조 (단건 자원 ID 규격 검증 및 일치 확인)
  const parsedTargetId = parseMemoResourceId(String(target.id ?? ''));
  const parsedBackupId = parseMemoResourceId(String(backupSample.id ?? ''));
  if (!parsedTargetId || parsedTargetId.type !== 'memo') {
    return { valid: false, reason: 'invalid_memo_resource_id' };
  }
  if (!parsedBackupId || parsedTargetId.id !== parsedBackupId.id) {
    return { valid: false, reason: 'id_mismatch' };
  }

  // 2. 소유자 대조 (사본의 owner_id, 대상의 owner_id, 로그인 사용자 ID 일치)
  const targetOwner = target.owner_id;
  const backupOwner = backupSample.owner_id;
  if (!targetOwner || !UUID.test(targetOwner)) {
    return { valid: false, reason: 'invalid_owner_id' };
  }
  if (targetOwner !== backupOwner) {
    return { valid: false, reason: 'owner_mismatch' };
  }
  if (verifiedUserId && targetOwner !== verifiedUserId) {
    return { valid: false, reason: 'owner_not_matching_verified_user' };
  }

  // 3. 내용 해시 대조 (사본의 contentHash와 복원 내용의 실시간 계산 해시 대조)
  const content = target.content ?? target.body ?? '';
  const calculatedHash = computeContentHash(content);
  const expectedHash = backupSample.contentHash || computeContentHash(backupSample.content ?? backupSample.body ?? '');

  if (target.contentHash && target.contentHash !== calculatedHash) {
    return { valid: false, reason: 'content_hash_integrity_failed' };
  }
  if (calculatedHash !== expectedHash) {
    return { valid: false, reason: 'content_hash_mismatch' };
  }

  return {
    valid: true,
    verifiedId: parsedTargetId.id,
    resourceId: createResourceId('memo', parsedTargetId.id),
    ownerId: targetOwner,
    contentHash: calculatedHash,
    title: target.title ?? backupSample.title ?? '복원된 메모',
    content,
  };
}
