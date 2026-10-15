import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseMemoResourceId, createResourceId } from './resource-id.mjs';
let backupNotesData = null;
try {
  const dataPath = path.join(import.meta.dirname, '..', 'data', 'backup-notes.json');
  if (fs.existsSync(dataPath)) {
    backupNotesData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
  }
} catch {}

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
export const BUILTIN_BACKUP_NOTES = Object.freeze(
  Array.isArray(backupNotesData) && backupNotesData.length > 0
    ? backupNotesData.map(item => Object.freeze({ ...item }))
    : [
        {
          id: '00000000-0000-4000-8000-00000000000b',
          owner_id: '00000000-0000-4000-8000-00000000000b',
          title: '시험 계정 B 업무 일지 사본',
          content: '시험 계정 B의 3차 침공 전 검증된 비공개 가상 메모 본문입니다.',
          contentHash: 'eef8755315bd87e7cdfa6c54ae226e96a57b0c6c839e0add4cd3a58ba8fb5e2f',
          version: 'backup_v1',
        },
        {
          id: '00000000-0000-4000-8000-000000000001',
          owner_id: '00000000-0000-4000-8000-00000000000b',
          title: '시험 계정 B 업무 일지 사본',
          content: '시험 계정 B의 3차 침공 전 검증된 비공개 가상 메모 본문입니다.',
          contentHash: 'eef8755315bd87e7cdfa6c54ae226e96a57b0c6c839e0add4cd3a58ba8fb5e2f',
          version: 'backup_v1',
        },
      ]
);

function verifyLoadedBackup(item) {
  if (!item || typeof item !== 'object') return null;
  const content = item.content ?? item.body;
  const declaredHash = item.contentHash ?? item.hash;
  if (!content || !declaredHash) return null;
  if (computeContentHash(content) !== declaredHash) return null;
  return Object.freeze({ ...item });
}

/**
 * 저장소의 비공개 가상 메모 사본 파일 및 내장 사본에서 지정한 ID의 사본을 다시 읽어옵니다.
 * 사본을 다시 읽은 뒤 내용 해시를 실시간 검증하며, 사본이 없거나 검증 실패 시 즉시 null을 반환하여 멈춥니다.
 */
export function loadBackupNote(targetId, ownerId) {
  if (!targetId) return null; // 대상 ID가 주어지지 않으면 임의 기본값 폴백 없이 즉시 null (사본 부재 중단)

  const parsedTarget = parseMemoResourceId(String(targetId));
  const cleanId = parsedTarget?.id ?? String(targetId);
  if (!cleanId || !UUID.test(cleanId)) return null;

  // 1. 파일에서 먼저 실시간으로 다시 읽기 시도 및 무결성 검증 (다양한 런타임 경로)
  const candidatePaths = [
    path.join(process.cwd(), 'data', 'backup-notes.json'),
    path.join(import.meta.dirname, '..', 'data', 'backup-notes.json'),
  ];

  let fileChecked = false;
  for (const backupPath of candidatePaths) {
    try {
      if (fs.existsSync(backupPath)) {
        fileChecked = true;
        const raw = fs.readFileSync(backupPath, 'utf8');
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          const found = list.find(item => {
            const parsedItem = parseMemoResourceId(String(item.id ?? ''));
            return (parsedItem?.id ?? item.id) === cleanId;
          });
          if (!found) {
            // 파일이 존재하는데 해당 ID가 없으면 임의 폴백 없이 즉시 중단(null)
            return null;
          }
          // 사본을 다시 읽은 뒤 내용 해시 검증. 실패 시 null 반환하여 즉시 멈춤
          return verifyLoadedBackup(found);
        }
        return null;
      }
    } catch {
      // 파일 파싱 실패(손상/변조) 시 즉시 중단(null)
      return null;
    }
  }

  // 파일이 아예 존재하지 않는 특수 런타임 환경에서만 정적 번들/내장 사본 참조
  if (!fileChecked) {
    if (Array.isArray(backupNotesData)) {
      const found = backupNotesData.find(item => {
        const parsedItem = parseMemoResourceId(String(item.id ?? ''));
        return (parsedItem?.id ?? item.id) === cleanId;
      });
      if (found) {
        return verifyLoadedBackup(found);
      }
    }

    const builtin = BUILTIN_BACKUP_NOTES.find(item => {
      const parsedItem = parseMemoResourceId(String(item.id ?? ''));
      return (parsedItem?.id ?? item.id) === cleanId;
    });
    if (builtin) {
      return verifyLoadedBackup(builtin);
    }
  }

  return null;
}

/**
 * 요청 본문에서 지정한 ID에 해당하는 사본 객체를 추출합니다.
 * 사본이 배열이거나 객체인 경우 모두 지원하며, 변조 여부 대조를 위해 빠짐없이 추출합니다.
 */
export function extractBackupSource(body, targetId, ownerId) {
  if (!body || typeof body !== 'object') return null;

  const parsedTarget = targetId ? parseMemoResourceId(String(targetId)) : null;
  const cleanId = parsedTarget?.id ?? (targetId ? String(targetId) : null);

  // 1) body.backup이 배열인 경우
  if (Array.isArray(body.backup)) {
    if (cleanId) {
      const found = body.backup.find(item => {
        const p = parseMemoResourceId(String(item.id ?? ''));
        return (p?.id ?? item.id) === cleanId;
      });
      if (found) return found;
    }
    if (body.backup.length > 0) return body.backup[0];
  }

  // 2) body.backup.notes가 배열인 경우
  if (Array.isArray(body.backup?.notes)) {
    if (cleanId) {
      const found = body.backup.notes.find(item => {
        const p = parseMemoResourceId(String(item.id ?? ''));
        return (p?.id ?? item.id) === cleanId;
      });
      if (found) return found;
    }
    if (body.backup.notes.length > 0) return body.backup.notes[0];
  }

  // 3) body.backup이 단건 객체인 경우 (id 존재 여부와 무관하게 변조 검증을 위해 추출)
  if (body.backup && typeof body.backup === 'object' && !Array.isArray(body.backup)) {
    return body.backup;
  }

  // 4) body.backupNotes 또는 body.notes가 배열인 경우
  const candidateList = Array.isArray(body.backupNotes) ? body.backupNotes : (Array.isArray(body.notes) ? body.notes : null);
  if (candidateList) {
    if (cleanId) {
      const found = candidateList.find(item => {
        const p = parseMemoResourceId(String(item.id ?? ''));
        return (p?.id ?? item.id) === cleanId;
      });
      if (found) return found;
    }
    if (candidateList.length > 0) return candidateList[0];
  }

  // 5) body.memo 또는 body.target인 경우
  if (body.memo && typeof body.memo === 'object') return body.memo;
  if (body.target && typeof body.target === 'object') return body.target;

  // 6) body 자체가 단건 사본/대상이고 content 또는 hash가 있는 경우 (변조 검증 대상)
  if (body.content !== undefined || body.body !== undefined || body.text !== undefined || body.contentHash !== undefined || body.hash !== undefined) {
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
  if (!target || typeof target !== 'object' || Object.keys(target).length === 0) {
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
  const targetRawId = target.id ?? target.resourceId;
  if (!targetRawId && !target.content && !target.contentHash) {
    return { valid: false, reason: 'missing_target_id', message: '복구 대상 ID가 지정되지 않았습니다.' };
  }

  if (targetRawId) {
    const parsedTargetId = parseMemoResourceId(String(targetRawId));
    const parsedBackupId = parseMemoResourceId(String(backupSample.id ?? ''));
    if (!parsedTargetId || parsedTargetId.type !== 'memo') {
      return { valid: false, reason: 'invalid_memo_resource_id', message: '올바른 메모 자원 ID가 아닙니다.' };
    }
    if (parsedBackupId && parsedTargetId.id !== parsedBackupId.id) {
      return { valid: false, reason: 'id_mismatch', message: '대상 ID가 사본의 ID와 일치하지 않습니다.' };
    }
  }

  // 2. 소유자 대조 (사본의 owner_id와 대상의 owner_id 일치 확인)
  if (target.owner_id) {
    if (!UUID.test(target.owner_id)) {
      return { valid: false, reason: 'invalid_owner_id', message: '올바른 소유자 ID가 아닙니다.' };
    }
    if (backupSample.owner_id && target.owner_id !== backupSample.owner_id) {
      return { valid: false, reason: 'owner_mismatch', message: '소유자가 사본의 소유자와 일치하지 않습니다.' };
    }
  }

  // 3. 내용 및 내용 해시 대조 (사본의 contentHash와 실시간 계산 해시 대조)
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

  const verifiedId = backupSample.id;
  return {
    valid: true,
    verifiedId,
    resourceId: createResourceId('memo', verifiedId),
    ownerId: backupSample.owner_id,
    contentHash: expectedHash,
    version: backupSample.version ?? 'backup_v1',
    title: backupSample.title ?? '복원된 메모',
    content: backupContent, // 반드시 검증된 사본의 원본 내용 사용!
  };
}
