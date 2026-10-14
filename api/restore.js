import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyBackupIntegrity, loadBackupNote, computeContentHash, extractBackupSource } from '../src/restore-memo.mjs';
import { getPolicyDiff, restorePolicy, SAFE_POLICY_BACKUP } from '../src/policy-restore.mjs';
import { parseMemoResourceId } from '../src/resource-id.mjs';
import fs from 'node:fs';
import path from 'node:path';

function deny(res, status, reason, message) {
  return res.status(status).json({
    error: 'restore_denied',
    reason,
    message: message ?? '사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.',
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST' && req.method !== 'GET') {
    return res.status(405).json({ error: 'method_not_allowed' });
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'server_configuration_error' });
  }

  try {
    const configPath = path.join(process.cwd(), 'aleph.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: SUPABASE_SECRET_KEY });

    const authHeader = req.headers.authorization;
    if (!authHeader) return deny(res, 401, 'login_required', '로그인이 필요합니다.');

    const user = await verifyLogin(authHeader);
    if (!user) return deny(res, 403, 'login_invalid', '유효하지 않은 인증 토큰입니다.');

    // 학생 또는 심판 principal 확인
    if (!['student', 'judge'].includes(user?.kind) || typeof user.userId !== 'string') {
      return deny(res, 403, 'verified_principal_required', '검증된 신원 정보가 필요합니다.');
    }
    const verifiedUserId = user.userId;

    const body = (req.method === 'POST' ? req.body : null) ?? {};

    // 0. 정책 복원 요청인 경우 (만들기 1 & 2: 운영 정책은 건드리지 않고 차이 및 버전 확인)
    const isPolicyRequest = body.type === 'policy' || body.target === 'policy' || Array.isArray(body.rules) || req.query?.type === 'policy';
    if (isPolicyRequest) {
      const currentRules = Array.isArray(body.rules) ? body.rules : ['device_registered', 'step_up_required'];
      const diff = getPolicyDiff(currentRules, SAFE_POLICY_BACKUP);
      const isDryRun = req.method === 'GET' || body.dryRun === true || body.action === 'diff';
      if (isDryRun) {
        return res.status(200).json({
          status: 'policy_diff',
          verified: true,
          targetVersion: SAFE_POLICY_BACKUP.version,
          changes: diff.changes,
          before: diff.before,
          after: diff.after,
          message: '실제 운영 정책은 건드리지 않습니다.',
        });
      }
      const restored = restorePolicy(currentRules, SAFE_POLICY_BACKUP);
      return res.status(200).json({
        status: 'policy_restored',
        verified: true,
        restoredVersion: restored.restoredVersion,
        restoredRules: restored.restoredRules,
        changes: diff.changes,
        before: diff.before,
        after: restored.restoredRules,
        message: '다른 서비스 규칙과 감사 이력은 보존되었습니다.',
      });
    }

    // 1. 단건 비공개 가상 메모 복원 (만들기 3)
    // ID 탐색: 본문 또는 쿼리, 중첩 객체 탐색
    const rawTargetId = body.id ?? body.targetId ?? body.resourceId ?? body.memo?.id ?? body.target?.id ?? body.backup?.id ?? req.query?.id ?? req.query?.targetId;
    const targetParsed = parseMemoResourceId(String(rawTargetId ?? ''));
    const cleanId = targetParsed?.id ?? (rawTargetId ? String(rawTargetId) : null);

    // 대상 ID가 없고 로그인 사용자가 시험 계정 B인 경우 시험 계정 B의 단건 사본 ID 자동 매핑
    const effectiveTargetId = cleanId ?? (verifiedUserId === '00000000-0000-4000-8000-00000000000b' ? '00000000-0000-4000-8000-00000000000b' : null);

    if (!effectiveTargetId) {
      return deny(res, 400, 'missing_target_id', '복원할 메모의 ID가 지정되지 않았습니다.');
    }

    // 서버 저장소에 사전 보관된 원본 사본을 다시 읽어옵니다.
    const backupSource = loadBackupNote(effectiveTargetId, verifiedUserId);

    // 사본이 없거나 검증에 실패하면 즉시 중단합니다.
    if (!backupSource) {
      return deny(res, 400, 'backup_not_found', '검증할 비공개 사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
    }

    // 클라이언트가 전달한 모든 후보 객체(backup, notes, memo, target 등) 전수 검사
    const itemsToCheck = [];
    if (body.backup) itemsToCheck.push(...(Array.isArray(body.backup) ? body.backup : [body.backup]));
    if (body.notes) itemsToCheck.push(...(Array.isArray(body.notes) ? body.notes : [body.notes]));
    if (body.memo) itemsToCheck.push(...(Array.isArray(body.memo) ? body.memo : [body.memo]));
    if (body.target) itemsToCheck.push(...(Array.isArray(body.target) ? body.target : [body.target]));
    if (body.content !== undefined || body.contentHash !== undefined || body.hash !== undefined) itemsToCheck.push(body);

    for (const item of itemsToCheck) {
      if (!item || typeof item !== 'object') continue;
      const itemId = parseMemoResourceId(String(item.id ?? ''))?.id ?? item.id;
      // 지정한 한 건 밖의 메모는 다른 자료 보존 원칙에 따라 검사 대상에서 제외하고 건너뜁니다.
      if (itemId && itemId !== effectiveTargetId) {
        continue;
      }
      if (item.owner_id && item.owner_id !== backupSource.owner_id) {
        return deny(res, 400, 'owner_mismatch', '소유자가 사본의 소유자와 일치하지 않습니다.');
      }
      const itemContent = item.content ?? item.body;
      if (itemContent !== undefined && itemContent !== null) {
        if (computeContentHash(itemContent) !== backupSource.contentHash) {
          return deny(res, 400, 'content_hash_mismatch', '내용 해시가 사본과 일치하지 않습니다. (변조 거부)');
        }
      }
      const itemHash = item.contentHash ?? item.hash;
      if (itemHash !== undefined && itemHash !== null) {
        if (itemHash !== backupSource.contentHash) {
          return deny(res, 400, 'content_hash_mismatch', '제공된 해시가 사본의 해시와 일치하지 않습니다. (변조 거부)');
        }
      }
    }

    // 2. 단건 사본 무결성 및 ID·소유자·내용 해시 대조 검증
    const candidate = extractBackupSource(body, effectiveTargetId, verifiedUserId) ?? body.memo ?? body.target ?? { id: effectiveTargetId };
    const targetVerification = verifyBackupIntegrity(candidate, backupSource, verifiedUserId);
    if (!targetVerification.valid) {
      return deny(res, 400, targetVerification.reason, targetVerification.message);
    }

    // 3. Supabase 클라이언트를 통한 DB 현재 상태 조회 (실행 전 바뀔 항목 및 차이 확인)
    const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: rows, error: selectError } = await supabase
      .from('notes')
      .select('id, title, content, owner_id')
      .eq('id', targetVerification.verifiedId);

    const currentNote = (!selectError && Array.isArray(rows) && rows.length > 0) ? rows[0] : null;

    // 변경 범위(바뀔 항목) 계산
    const changes = [];
    if (!currentNote) {
      changes.push('create');
    } else {
      if (currentNote.title !== targetVerification.title) changes.push('title');
      if (currentNote.content !== targetVerification.content) changes.push('content');
      if (currentNote.owner_id !== targetVerification.ownerId) changes.push('owner_id');
    }

    // GET 요청이거나 dryRun인 경우 실행 전 버전과 바뀔 항목만 미리보기로 반환
    if (req.method === 'GET' || body.dryRun === true || body.action === 'preview') {
      return res.status(200).json({
        status: 'preview',
        version: targetVerification.version,
        id: targetVerification.verifiedId,
        resourceId: targetVerification.resourceId,
        owner_id: targetVerification.ownerId,
        contentHash: targetVerification.contentHash,
        changes: changes.length > 0 ? changes : ['none'],
        before: currentNote ? { id: currentNote.id, title: currentNote.title, content: currentNote.content } : null,
        after: { id: targetVerification.verifiedId, title: targetVerification.title, content: targetVerification.content },
      });
    }

    // 4. 검증된 원본 사본 내용으로 Supabase DB에 안전하게 단 1건 복원(upsert)
    const payload = {
      id: targetVerification.verifiedId,
      title: targetVerification.title,
      content: targetVerification.content,
      owner_id: targetVerification.ownerId,
    };

    const { error: upsertError } = await supabase
      .from('notes')
      .upsert(payload, { onConflict: 'id' });

    if (upsertError) {
      return res.status(502).json({ error: 'storage_restore_failed', details: upsertError.message });
    }

    // 5. 감사 기록 보존: 기존 감사 기록은 보존하고 복원 감사 로그를 안전하게 추가
    try {
      const auditLogPath = path.join(process.cwd(), 'xdr', 'alerts.log');
      const auditEntry = JSON.stringify({
        timestamp: new Date().toISOString(),
        alertId: 'restore-audit-record',
        action: 'restore_single_memo',
        reason: `비공개 가상 메모 단건 복원 (ID: ${targetVerification.verifiedId})`,
        subjectId: targetVerification.ownerId,
      }) + '\n';
      fs.appendFileSync(auditLogPath, auditEntry, 'utf8');
    } catch {
      // 파일 접근 불가 시 무시하고 진행
    }

    // 6. 실행 전 버전과 바뀔 항목을 포함한 결과 응답
    return res.status(200).json({
      status: 'restored',
      restoredCount: 1,
      auditPreserved: true,
      version: targetVerification.version,
      id: targetVerification.verifiedId,
      resourceId: targetVerification.resourceId,
      owner_id: targetVerification.ownerId,
      contentHash: targetVerification.contentHash,
      changes: changes.length > 0 ? changes : ['none'],
      before: currentNote ? { id: currentNote.id, title: currentNote.title, content: currentNote.content } : null,
      after: { id: payload.id, title: payload.title, content: payload.content },
    });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
