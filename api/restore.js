import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyBackupIntegrity, loadBackupNote, computeContentHash } from '../src/restore-memo.mjs';
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
  if (req.method !== 'POST') {
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

    const body = req.body ?? {};
    const candidate = body.memo ?? body;
    const targetId = candidate.id ?? candidate.resourceId ?? body.id ?? body.backup?.id;

    if (!targetId) {
      return deny(res, 400, 'missing_target_id', '복원할 메모의 ID가 지정되지 않았습니다.');
    }

    // 1. 사본(Backup) 확보:
    // 클라이언트가 명시적인 사본 원본 객체(backup)를 제공했거나, 저장소의 검증된 사본 파일에서 다시 읽어옵니다.
    let backupSource = null;
    if (body.backup && typeof body.backup === 'object' && body.backup.content && (body.backup.contentHash || body.backup.hash)) {
      backupSource = body.backup;
    } else {
      backupSource = loadBackupNote(targetId);
    }

    // 사본이 없거나 찾을 수 없으면 즉시 중단
    if (!backupSource) {
      return deny(res, 400, 'backup_not_found', '검증할 비공개 사본이 없거나 검증에 실패하여 멈춥니다. 실제 운영 정책은 건드리지 않습니다.');
    }

    // 2. 사본 무결성 및 ID·소유자·내용 해시 대조 검증
    const targetVerification = verifyBackupIntegrity(candidate, backupSource, verifiedUserId);
    if (!targetVerification.valid) {
      // 검증 실패 시 복원하지 않고 멈춥니다.
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
      // DB 조회 실패 시에도 계속 진행
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

    // 4. 다른 메모와 감사 기록은 보존하며 검증된 사본 원본으로 단 1건만 복원(upsert)
    const payload = {
      id: targetVerification.verifiedId,
      title: targetVerification.title,
      content: targetVerification.content,
      owner_id: targetVerification.ownerId,
    };

    const response = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates,return=representation',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      return res.status(502).json({ error: 'storage_restore_failed' });
    }

    // 5. 실행 전 버전과 바뀔 항목을 포함한 결과 응답
    return res.status(200).json({
      status: 'restored',
      restoredCount: 1,
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
