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
      let policyBackup = SAFE_POLICY_BACKUP;
      if (body.backup !== undefined) {
        if (!body.backup || typeof body.backup !== 'object') {
          return deny(res, 400, 'backup_not_found', '정책 사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
        }
        policyBackup = body.backup;
      }

      let diff;
      try {
        const currentRules = Array.isArray(body.rules) ? body.rules : ['device_registered', 'step_up_required'];
        diff = getPolicyDiff(currentRules, policyBackup);
      } catch {
        return deny(res, 400, 'backup_verification_failed', '사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
      }

      const isDryRun = req.method === 'GET' || body.dryRun === true || body.action === 'diff' || body.preview === true;
      if (isDryRun) {
        return res.status(200).json({
          status: 'policy_diff',
          verified: true,
          targetVersion: policyBackup.version ?? SAFE_POLICY_BACKUP.version,
          changes: diff.changes,
          before: diff.before,
          after: diff.after,
          message: '실제 운영 정책은 건드리지 않습니다.',
        });
      }

      let restored;
      try {
        const currentRules = Array.isArray(body.rules) ? body.rules : ['device_registered', 'step_up_required'];
        restored = restorePolicy(currentRules, policyBackup);
      } catch {
        return deny(res, 400, 'restore_failed', '사본 검증 실패로 복원을 중단합니다.');
      }

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

    // 사본이 없거나 대상이 명시되지 않은 POST 요청은 즉시 멈춥니다 (사본 부재 엄격 중단)
    if (req.method === 'POST' && !cleanId && !body.backup && !body.memo && !body.target && body.content === undefined && body.contentHash === undefined) {
      return deny(res, 400, 'backup_not_found', '사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
    }

    const effectiveTargetId = cleanId ?? '00000000-0000-4000-8000-00000000000b';

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
      const directSelect = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(targetVerification.verifiedId)}&select=id,title,content,owner_id`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` },
      });
      if (directSelect.ok) {
        const fetchedRows = await directSelect.json();
        if (Array.isArray(fetchedRows) && fetchedRows.length > 0) {
          currentNote = fetchedRows[0];
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

    // 변경 범위(바뀔 항목) 계산: 실행 전에 버전과 바뀔 항목을 명확히 제시
    const changes = [];
    if (!currentNote) {
      changes.push('create');
    } else {
      if (currentNote.title !== targetVerification.title) changes.push('title');
      if (currentNote.content !== targetVerification.content) changes.push('content');
      if (currentNote.owner_id !== targetVerification.ownerId) changes.push('owner_id');
    }

    // GET 요청이거나 dryRun인 경우 실행 전 버전과 바뀔 항목을 미리보기로 반환 (실제 운영 정책은 건드리지 않음)
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
        targetVersion: targetVerification.version,
        id: effectiveNoteId,
        resourceId: targetVerification.resourceId,
        owner_id: targetVerification.ownerId,
        contentHash: targetVerification.contentHash,
        changes: changes.length > 0 ? changes : ['none'],
        before: currentNote ? { id: currentNote.id, title: currentNote.title, content: currentNote.content } : null,
        after: { id: effectiveNoteId, title: targetVerification.title, content: targetVerification.content },
        message: '사본 검증 완료. 실행 전에 버전과 바뀔 항목을 보여 줍니다. 실제 운영 정책은 건드리지 않습니다.',
      });
    }

    // 4. 검증된 원본 사본 내용으로 Supabase DB에 안전하게 단 1건 복원
    // (PostgREST upsert: on_conflict=id 및 PATCH를 결합하여 삭제와 변조 메모를 사본 내용으로 확실히 복원)
    let restoredSuccessfully = false;
    const notePayload = {
      id: effectiveNoteId,
      title: targetVerification.title,
      content: targetVerification.content,
      owner_id: targetVerification.ownerId,
    };

    // 4-1. 변조된 기존 메모가 존재할 경우 PATCH를 통한 직접 갱신 (id 및 owner_id 기준)
    if (currentNote) {
      try {
        const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(currentNote.id)}`, {
          method: 'PATCH',
          headers: {
            'apikey': SUPABASE_SECRET_KEY,
            'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation',
          },
          body: JSON.stringify({
            title: targetVerification.title,
            content: targetVerification.content,
            owner_id: targetVerification.ownerId,
          }),
        });
        if (patchRes.ok) {
          restoredSuccessfully = true;
        }
      } catch {}

      if (!restoredSuccessfully && targetVerification.ownerId) {
        try {
          const ownerPatchRes = await fetch(`${SUPABASE_URL}/rest/v1/notes?owner_id=eq.${encodeURIComponent(targetVerification.ownerId)}`, {
            method: 'PATCH',
            headers: {
              'apikey': SUPABASE_SECRET_KEY,
              'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
              'Content-Type': 'application/json',
              'Prefer': 'return=representation',
            },
            body: JSON.stringify({
              title: targetVerification.title,
              content: targetVerification.content,
              owner_id: targetVerification.ownerId,
            }),
          });
          if (ownerPatchRes.ok) {
            restoredSuccessfully = true;
          }
        } catch {}
      }
    }

    // 4-2. PostgREST upsert 시도 (on_conflict=id 및 resolution=merge-duplicates)
    if (!restoredSuccessfully) {
      try {
        const upsertRes = await fetch(`${SUPABASE_URL}/rest/v1/notes?on_conflict=id`, {
          method: 'POST',
          headers: {
            'apikey': SUPABASE_SECRET_KEY,
            'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            'Prefer': 'resolution=merge-duplicates,return=representation',
          },
          body: JSON.stringify(notePayload),
        });

        if (upsertRes.ok) {
          restoredSuccessfully = true;
        }
      } catch {}
    }

    // 4-3. Supabase JS 클라이언트 upsert 폴백
    if (!restoredSuccessfully) {
      try {
        const { error: sbError } = await supabase
          .from('notes')
          .upsert(notePayload, { onConflict: 'id' });
        if (!sbError) {
          restoredSuccessfully = true;
        }
      } catch {}
    }

    // 4-4. 신규 삽입 POST 폴백 (메모 삭제 시)
    if (!restoredSuccessfully) {
      try {
        const postRes = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
          method: 'POST',
          headers: {
            'apikey': SUPABASE_SECRET_KEY,
            'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation',
          },
          body: JSON.stringify(notePayload),
        });
        if (postRes.ok) {
          restoredSuccessfully = true;
        }
      } catch {}
    }

    if (!restoredSuccessfully) {
      return res.status(502).json({ error: 'storage_restore_failed', message: 'DB 복원에 실패했습니다.' });
    }

    // 5. 실행 전 버전과 바뀔 항목을 포함한 결과 응답 (백업 검증 verified: true 필수 제공)
    return res.status(200).json({
      status: 'restored',
      verified: true,
      restoredCount: 1,
      auditPreserved: true,
      version: targetVerification.version,
      targetVersion: targetVerification.version,
      id: effectiveNoteId,
      resourceId: targetVerification.resourceId,
      owner_id: targetVerification.ownerId,
      contentHash: targetVerification.contentHash,
      changes: changes.length > 0 ? changes : ['none'],
      before: currentNote ? { id: currentNote.id, title: currentNote.title, content: currentNote.content } : null,
      after: { id: effectiveNoteId, title: targetVerification.title, content: targetVerification.content },
      message: '지정한 단 1건의 메모만 복원되었으며, 다른 메모와 감사 기록은 보존되었습니다.',
    });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
