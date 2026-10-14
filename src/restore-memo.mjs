import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
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
 * 저장소의 비공개 가상 메모 사본 파일에서 지정한 ID의 사본을 다시 읽어옵니다.
 */
export function loadBackupNote(targetId) {
  try {
    const backupPath = path.join(process.cwd(), 'data', 'backup-notes.json');
    if (!fs.existsSync(backupPath)) return null;
    const raw = fs.readFileSync(backupPath, 'utf8');
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return null;

    const parsedTarget = parseMemoResourceId(String(targetId ?? ''));
    const cleanId = parsedTarget?.id ?? String(targetId ?? '');

    const found = list.find(item => {
      const parsedItem = parseMemoResourceId(String(item.id ?? ''));
      return (parsedItem?.id ?? item.id) === cleanId;
    });
    return found ? Object.freeze({ ...found }) : null;
  } catch {
    return null;
  }
}

/**
 * 복구 대상 단건 사본의 ID·소유자·내용 해시를 신뢰할 수 있는 원본 사본과 대조하여 검증합니다.
 * 사본이 없거나 검증에 실패하면 즉시 중단합니다.
 * @param {object} target - 복원 대상 후보 ({ id, owner_id, content, contentHash })
 * @param {object} backupSample - 신뢰할 수 있는 비공개 사본 원본 객체
 * @param {string} verifiedUserId - 인증된 사용자 ID
 */
export function verifyBackupIntegrity(target, backupSample, verifiedUserId) {
  if (!backupSample || typeof backupSample !== 'object') {
    return { valid: false, reason: 'backup_not_found', message: '사본이 없거나 검증에 실패하여 멈춥니다.' };
  }
  if (!target || typeof target !== 'object') {
    return { valid: false, reason: 'missing_target', message: '복구 대상 정보가 없습니다.' };
  }

  // 1. ID 대조 (단건 자원 ID 규격 검증 및 사본 ID와 일치 확인)
  const parsedTargetId = parseMemoResourceId(String(target.id ?? ''));
  const parsedBackupId = parseMemoResourceId(String(backupSample.id ?? ''));
  if (!parsedTargetId || parsedTargetId.type !== 'memo') {
    return { valid: false, reason: 'invalid_memo_resource_id', message: '올바른 메모 자원 ID가 아닙니다.' };
  }
  if (!parsedBackupId || parsedTargetId.id !== parsedBackupId.id) {
    return { valid: false, reason: 'id_mismatch', message: '대상 ID가 사본의 ID와 일치하지 않습니다.' };
  }

  // 2. 소유자 대조 (사본의 owner_id, 대상의 owner_id, 로그인 사용자 ID 일치)
  const targetOwner = target.owner_id ?? verifiedUserId;
  const backupOwner = backupSample.owner_id;
  if (!targetOwner || !UUID.test(targetOwner)) {
    return { valid: false, reason: 'invalid_owner_id', message: '올바른 소유자 ID가 아닙니다.' };
  }
  if (targetOwner !== backupOwner) {
    return { valid: false, reason: 'owner_mismatch', message: '소유자가 사본의 소유자와 일치하지 않습니다.' };
  }
  if (verifiedUserId && targetOwner !== verifiedUserId) {
    return { valid: false, reason: 'owner_not_matching_verified_user', message: '인증된 사용자의 메모만 복원할 수 있습니다.' };
  }

  // 3. 내용 해시 대조 (사본의 contentHash와 실시간 계산 해시 대조)
  const expectedHash = backupSample.contentHash || computeContentHash(backupSample.content ?? backupSample.body ?? '');
  if (!expectedHash) {
    return { valid: false, reason: 'backup_hash_missing', message: '사본의 내용 해시 정보가 없습니다.' };
  }

  // 만약 대상 객체에 내용(content)이 전달된 경우, 실시간 계산 해시 대조
  const candidateContent = target.content ?? target.body;
  if (candidateContent !== undefined && candidateContent !== null) {
    const candidateHash = computeContentHash(candidateContent);
    if (candidateHash !== expectedHash) {
      return { valid: false, reason: 'content_hash_mismatch', message: '내용 해시가 사본과 일치하지 않습니다. (변조 거부)' };
    }
  }

  // 만약 대상 객체에 contentHash가 직접 전달된 경우, 사본 해시와 대조
  if (target.contentHash && target.contentHash !== expectedHash) {
    return { valid: false, reason: 'content_hash_mismatch', message: '제공된 해시가 사본의 해시와 일치하지 않습니다.' };
  }

  return {
    valid: true,
    verifiedId: parsedTargetId.id,
    resourceId: createResourceId('memo', parsedTargetId.id),
    ownerId: targetOwner,
    contentHash: expectedHash,
    version: backupSample.version ?? 'backup_v1',
    title: backupSample.title ?? target.title ?? '복원된 메모',
    content: backupSample.content ?? backupSample.body, // 반드시 사본의 원본 내용 사용!
  };
}
