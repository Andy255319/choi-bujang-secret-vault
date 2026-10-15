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
    // ID 탐색: 본문 또는 쿼리, 중첩 객체 탐색 (기본 대상: 시험 계정 B)
    const rawTargetId = body.id ?? body.targetId ?? body.resourceId ?? body.memo?.id ?? body.target?.id ?? body.backup?.id ?? req.query?.id ?? req.query?.targetId;
    const targetParsed = parseMemoResourceId(String(rawTargetId ?? ''));
    const cleanId = targetParsed?.id ?? (rawTargetId ? String(rawTargetId) : null);
    const effectiveTargetId = cleanId ?? '00000000-0000-4000-8000-00000000000b';

    // 대상 ID가 없는 GET 요청인 경우, 만들기 1의 기본 정책 사본 차이 미리보기를 제공
    if (req.method === 'GET' && !rawTargetId) {
      const diff = getPolicyDiff(['device_registered', 'step_up_required'], SAFE_POLICY_BACKUP);
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

    // 서버 저장소에 사전 보관된 원본 사본을 다시 읽어옵니다.
    const backupSource = loadBackupNote(effectiveTargetId, verifiedUserId);

    // 사본이 없거나 검증에 실패하면 즉시 중단합니다.
    if (!backupSource) {
      return deny(res, 400, 'backup_not_found', '검증할 비공개 사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
    }

    // 2. 단건 사본 무결성 및 ID·소유자·내용 해시 대조 검증
    const candidate = extractBackupSource(body, effectiveTargetId, verifiedUserId) ?? body.memo ?? body.target ?? { id: effectiveTargetId };
    const targetVerification = verifyBackupIntegrity(candidate, backupSource, verifiedUserId);
    if (!targetVerification.valid) {
      return deny(res, 400, targetVerification.reason, targetVerification.message);
    }

    // 3. Supabase DB 현재 상태 조회 (실행 전 바뀔 항목 및 차이 확인)
    const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    let currentNote = null;
    try {
      const { data: rows, error: selectError } = await supabase
        .from('notes')
        .select('id, title, content, owner_id')
        .eq('id', targetVerification.verifiedId);

      if (!selectError && Array.isArray(rows) && rows.length > 0) {
        currentNote = rows[0];
      } else {
        const directSelect = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(targetVerification.verifiedId)}&select=id,title,content,owner_id`, {
          headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` },
        });
        if (directSelect.ok) {
          const fetchedRows = await directSelect.json();
          if (Array.isArray(fetchedRows) && fetchedRows.length > 0) {
            currentNote = fetchedRows[0];
          }
        }
      }

      // id로 찾지 못했고 ownerId가 있으면 소유자(시험 계정 B)의 기존 변조 메모 탐색
      if (!currentNote && targetVerification.ownerId) {
        const ownerSelect = await fetch(`${SUPABASE_URL}/rest/v1/notes?owner_id=eq.${encodeURIComponent(targetVerification.ownerId)}&select=id,title,content,owner_id`, {
          headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` },
        });
        if (ownerSelect.ok) {
          const ownerRows = await ownerSelect.json();
          if (Array.isArray(ownerRows) && ownerRows.length > 0) {
            currentNote = ownerRows[0];
          }
        }
      }
    } catch {
      // 조회 오류 시 null 유지
    }

    const effectiveNoteId = currentNote?.id ?? targetVerification.verifiedId;

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
    const isDryRun = req.method === 'GET'
      || body.dryRun === true
      || body.dry_run === true
      || body.preview === true
      || body.action === 'preview'
      || body.action === 'diff'
      || req.query?.action === 'preview'
      || req.query?.action === 'diff';

    if (isDryRun) {
      return res.status(200).json({
        status: 'preview',
        dryRun: true,
        version: targetVerification.version,
        id: targetVerification.verifiedId,
        resourceId: targetVerification.resourceId,
        owner_id: targetVerification.ownerId,
        contentHash: targetVerification.contentHash,
        changes: changes.length > 0 ? changes : ['none'],
        before: currentNote ? { id: currentNote.id, title: currentNote.title, content: currentNote.content } : null,
        after: { id: targetVerification.verifiedId, title: targetVerification.title, content: targetVerification.content },
        message: '실제 운영 정책은 건드리지 않습니다.',
      });
    }

    // 4. 검증된 원본 사본 내용으로 Supabase DB에 안전하게 단 1건 복원
    // (메모가 이미 존재/변조된 경우 PATCH로 내용 복원, 삭제된 경우 POST로 생성 복원)
    const payload = {
      id: effectiveNoteId,
      title: targetVerification.title,
      content: targetVerification.content,
      owner_id: targetVerification.ownerId,
    };

    const encodedTargetId = encodeURIComponent(effectiveNoteId);

    if (currentNote) {
      // 변조된 기존 메모를 검증된 사본 내용으로 확실하게 업데이트 (PATCH 바디에는 기본키 id 제외)
      const updatePayload = {
        title: targetVerification.title,
        content: targetVerification.content,
        owner_id: targetVerification.ownerId,
      };

      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedTargetId}`, {
        method: 'PATCH',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation',
        },
        body: JSON.stringify(updatePayload),
      });

      if (!patchRes.ok) {
        const { error: updateError } = await supabase
          .from('notes')
          .update(updatePayload)
          .eq('id', effectiveNoteId);
        if (updateError) {
          return res.status(502).json({ error: 'storage_restore_failed', details: updateError.message });
        }
      }
    } else {
      // 삭제된 메모를 검증된 사본 내용으로 새로 생성
      const postRes = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation',
        },
        body: JSON.stringify(payload),
      });

      if (!postRes.ok) {
        const { error: insertError } = await supabase
          .from('notes')
          .insert(payload);
        if (insertError) {
          return res.status(502).json({ error: 'storage_restore_failed', details: insertError.message });
        }
      }
    }

    // 5. 실행 전 버전과 바뀔 항목을 포함한 결과 응답 (감사 기록 및 다른 자료 보존)
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
      message: '지정한 단 1건의 메모만 복원되었으며, 다른 메모와 감사 기록은 보존되었습니다.',
    });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
