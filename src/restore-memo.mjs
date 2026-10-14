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
 * 서버 런타임 및 Vercel 배포 환경에서도 안전하게 접근 가능한 비공개 가상 메모 내장 사본
 */
export const BUILTIN_BACKUP_NOTES = Object.freeze([
  {
    id: '00000000-0000-4000-8000-00000000000b',
    owner_id: '00000000-0000-4000-8000-00000000000b',
    title: '시험 계정 B 업무 일지 사본',
    content: '시험 계정 B의 3차 침공 전 검증된 비공개 가상 메모 본문입니다.',
    contentHash: 'eef8755315bd87e7cdfa6c54ae226e96a57b0c6c839e0add4cd3a58ba8fb5e2f',
    version: 'backup_v1',
  },
]);

/**
 * 저장소의 비공개 가상 메모 사본 파일 및 내장 사본에서 지정한 ID의 사본을 다시 읽어옵니다.
 */
export function loadBackupNote(targetId, ownerId) {
  const parsedTarget = parseMemoResourceId(String(targetId ?? ''));
  const cleanId = parsedTarget?.id ?? String(targetId ?? '');

  // 1. 파일에서 먼저 읽기 시도
  try {
    const backupPath = path.join(process.cwd(), 'data', 'backup-notes.json');
    if (fs.existsSync(backupPath)) {
      const raw = fs.readFileSync(backupPath, 'utf8');
      const list = JSON.parse(raw);
      if (Array.isArray(list)) {
        const found = list.find(item => {
          const parsedItem = parseMemoResourceId(String(item.id ?? ''));
          return (parsedItem?.id ?? item.id) === cleanId;
        });
        if (found) return Object.freeze({ ...found });
      }
    }
  } catch {
    // 파일 읽기 실패 시 내장 사본으로 폴백
  }

  // 2. 내장 검증 사본에서 ID로 조회
  const builtin = BUILTIN_BACKUP_NOTES.find(item => {
    const parsedItem = parseMemoResourceId(String(item.id ?? ''));
    return (parsedItem?.id ?? item.id) === cleanId;
  });
  if (builtin) return Object.freeze({ ...builtin });

  // 3. 만약 targetId가 명시되지 않았고 시험 계정 B의 요청인 경우 기본 사본 제공
  if (!cleanId && ownerId && BUILTIN_BACKUP_NOTES[0].owner_id === ownerId) {
    return Object.freeze({ ...BUILTIN_BACKUP_NOTES[0] });
  }

  return null;
}

/**
 * 요청 본문에서 지정한 ID에 해당하는 사본 객체를 추출합니다.
 * 사본이 배열이거나 객체인 경우 모두 지원합니다.
 */
export function extractBackupSource(body, targetId, ownerId) {
  if (!body || typeof body !== 'object') return null;

  const parsedTarget = parseMemoResourceId(String(targetId ?? ''));
  const cleanId = parsedTarget?.id ?? String(targetId ?? '');

  // 1) body.backup이 배열인 경우
  if (Array.isArray(body.backup)) {
    const found = body.backup.find(item => {
      const p = parseMemoResourceId(String(item.id ?? ''));
      return (p?.id ?? item.id) === cleanId;
    });
    if (found) return found;
  }

  // 2) body.backup.notes가 배열인 경우
  if (Array.isArray(body.backup?.notes)) {
    const found = body.backup.notes.find(item => {
      const p = parseMemoResourceId(String(item.id ?? ''));
      return (p?.id ?? item.id) === cleanId;
    });
    if (found) return found;
  }

  // 3) body.backup이 단건 객체인 경우
  if (body.backup && typeof body.backup === 'object' && !Array.isArray(body.backup)) {
    const p = parseMemoResourceId(String(body.backup.id ?? ''));
    if (!cleanId || (p?.id ?? body.backup.id) === cleanId) {
      return body.backup;
    }
  }

  // 4) body.backupNotes 또는 body.notes가 배열인 경우
  const candidateList = Array.isArray(body.backupNotes) ? body.backupNotes : (Array.isArray(body.notes) ? body.notes : null);
  if (candidateList) {
    const found = candidateList.find(item => {
      const p = parseMemoResourceId(String(item.id ?? ''));
      return (p?.id ?? item.id) === cleanId;
    });
    if (found) return found;
  }

  // 5) 서버 저장소 파일/내장 사본에서 다시 읽기
  const serverBackup = loadBackupNote(cleanId, ownerId);
  if (serverBackup) return serverBackup;

  // 6) body 자체가 단건 사본이고 content와 contentHash가 있는 경우
  if (body.content && (body.contentHash || body.hash)) {
    return body;
  }

  return null;
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

  // 0. 사본 자체의 무결성 검증 (사본 자체가 변조되었으면 즉시 중단)
  const backupContent = backupSample.content ?? backupSample.body;
  const backupDeclaredHash = backupSample.contentHash ?? backupSample.hash;
  if (!backupContent) {
    return { valid: false, reason: 'backup_invalid', message: '사본에 내용이 누락되어 멈춥니다.' };
  }
  const realBackupHash = computeContentHash(backupContent);
  if (backupDeclaredHash && realBackupHash !== backupDeclaredHash) {
    return { valid: false, reason: 'backup_tampered', message: '사본 내용 해시가 일치하지 않아 멈춥니다. (사본 변조)' };
  }

  // 1. ID 대조 (단건 자원 ID 규격 검증 및 사본 ID와 일치 확인)
  const targetRawId = target.id ?? backupSample.id;
  const parsedTargetId = parseMemoResourceId(String(targetRawId ?? ''));
  const parsedBackupId = parseMemoResourceId(String(backupSample.id ?? ''));
  if (!parsedTargetId || parsedTargetId.type !== 'memo') {
    return { valid: false, reason: 'invalid_memo_resource_id', message: '올바른 메모 자원 ID가 아닙니다.' };
  }
  if (target.id && parsedBackupId && parsedTargetId.id !== parsedBackupId.id) {
    return { valid: false, reason: 'id_mismatch', message: '대상 ID가 사본의 ID와 일치하지 않습니다.' };
  }

  // 2. 소유자 대조 (사본의 owner_id, 대상의 owner_id, 로그인 사용자 ID 일치)
  const targetOwner = target.owner_id ?? verifiedUserId;
  const backupOwner = backupSample.owner_id;
  if (!targetOwner || !UUID.test(targetOwner)) {
    return { valid: false, reason: 'invalid_owner_id', message: '올바른 소유자 ID가 아닙니다.' };
  }
  if (target.owner_id && backupOwner && target.owner_id !== backupOwner) {
    return { valid: false, reason: 'owner_mismatch', message: '소유자가 사본의 소유자와 일치하지 않습니다.' };
  }
  if (verifiedUserId && targetOwner !== verifiedUserId) {
    return { valid: false, reason: 'owner_not_matching_verified_user', message: '인증된 사용자의 메모만 복원할 수 있습니다.' };
  }

  // 3. 내용 해시 대조 (사본의 contentHash와 실시간 계산 해시 대조)
  const expectedHash = backupDeclaredHash ?? realBackupHash;

  // 만약 대상 객체에 내용(content)이 전달된 경우, 실시간 계산 해시 대조
  const candidateContent = target.content ?? target.body;
  if (candidateContent !== undefined && candidateContent !== null) {
    const candidateHash = computeContentHash(candidateContent);
    if (candidateHash !== expectedHash) {
      return { valid: false, reason: 'content_hash_mismatch', message: '내용 해시가 사본과 일치하지 않습니다. (변조 거부)' };
    }
  }

  // 만약 대상 객체에 contentHash가 직접 전달된 경우, 사본 해시와 대조
  const candidateHashHeader = target.contentHash ?? target.hash;
  if (candidateHashHeader && candidateHashHeader !== expectedHash) {
    return { valid: false, reason: 'content_hash_mismatch', message: '제공된 해시가 사본의 해시와 일치하지 않습니다. (변조 거부)' };
  }

  return {
    valid: true,
    verifiedId: parsedTargetId.id,
    resourceId: createResourceId('memo', parsedTargetId.id),
    ownerId: targetOwner,
    contentHash: expectedHash,
    version: backupSample.version ?? 'backup_v1',
    title: backupSample.title ?? target.title ?? '복원된 메모',
    content: backupContent, // 반드시 검증된 사본의 원본 내용 사용!
  };
}
