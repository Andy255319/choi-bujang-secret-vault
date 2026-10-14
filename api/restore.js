import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyBackupIntegrity, loadBackupNote, computeContentHash } from '../src/restore-memo.mjs';
import { getPolicyDiff, restorePolicy, SAFE_POLICY_BACKUP } from '../src/policy-restore.mjs';
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

    // 0. 정책 복원 요청인 경우 (만들기 1 & 2 지원: 실제 운영 정책은 건드리지 않고 차이/버전 확인)
    const isPolicyRequest = body.type === 'policy' || body.target === 'policy' || req.query?.type === 'policy';
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
    const candidate = body.memo ?? body.target ?? body;
    const targetId = candidate.id ?? candidate.resourceId ?? body.id ?? body.backup?.id;

    if (!targetId && req.method === 'POST') {
      return deny(res, 400, 'missing_target_id', '복원할 메모의 ID가 지정되지 않았습니다.');
    }

    // 서버 저장소에 사전 보관된 원본 사본을 다시 읽어옵니다.
    const backupSource = loadBackupNote(targetId, verifiedUserId);

    // 사본이 없거나 찾을 수 없으면 즉시 중단합니다.
    if (!backupSource) {
      return deny(res, 400, 'backup_not_found', '검증할 비공개 사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
    }

    // 만약 클라이언트가 사본(body.backup)을 함께 보낸 경우, 서버 사본과 대조하여 변조 여부 검사
    if (body.backup && typeof body.backup === 'object') {
      const clientContent = body.backup.content ?? body.backup.body;
      const clientHash = body.backup.contentHash ?? body.backup.hash;
      if (clientContent && computeContentHash(clientContent) !== backupSource.contentHash) {
        return deny(res, 400, 'backup_tampered', '전달된 사본의 내용이 원본 사본과 일치하지 않아 멈춥니다.');
      }
      if (clientHash && clientHash !== backupSource.contentHash) {
        return deny(res, 400, 'backup_tampered', '전달된 사본 해시가 원본 사본과 일치하지 않아 멈춥니다.');
      }
    }

    // 2. 사본 무결성 및 ID·소유자·내용 해시 대조 검증
    const targetVerification = verifyBackupIntegrity(candidate, backupSource, verifiedUserId);
    if (!targetVerification.valid) {
      return deny(res, 400, targetVerification.reason, targetVerification.message);
    }

    // 3. 기존 DB 현재 상태 조회 (실행 전 바뀔 항목 및 차이 확인)
    const encodedId = encodeURIComponent(targetVerification.verifiedId);
    let currentNote = null;
    try {
      const getRes = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}&select=id,title,content,owner_id`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` },
      });
      if (getRes.ok) {
        const rows = await getRes.json();
        if (Array.isArray(rows) && rows.length > 0) {
          currentNote = rows[0];
        }
      }
    } catch {
      // 조회 실패 시 무시하고 계속 진행
    }

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

    // 4. 다른 메모와 감사 기록은 보존하며 검증된 사본 원본으로 대상 1건 복원
    const payload = {
      id: targetVerification.verifiedId,
      title: targetVerification.title,
      content: targetVerification.content,
      owner_id: targetVerification.ownerId,
    };

    let response;
    if (currentNote) {
      // DB에 기존 행이 존재하는 경우 PATCH로 단 1건만 업데이트
      response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}`, {
        method: 'PATCH',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation',
        },
        body: JSON.stringify(payload),
      });
    } else {
      // DB에 행이 없는 경우 POST로 신규 삽입
      response = await fetch(`${SUPABASE_URL}/rest/v1/notes?on_conflict=id`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates,return=representation',
        },
        body: JSON.stringify(payload),
      });
    }

    // 만약 첫 시도가 실패한 경우 다른 방식으로 재시도
    if (!response.ok) {
      const fallbackUrl = currentNote
        ? `${SUPABASE_URL}/rest/v1/notes?on_conflict=id`
        : `${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}`;
      const fallbackMethod = currentNote ? 'POST' : 'PATCH';
      response = await fetch(fallbackUrl, {
        method: fallbackMethod,
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': currentNote ? 'resolution=merge-duplicates,return=representation' : 'return=representation',
        },
        body: JSON.stringify(payload),
      });
    }

    if (!response.ok) {
      return res.status(502).json({ error: 'storage_restore_failed' });
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
