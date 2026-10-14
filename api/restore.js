import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyBackupIntegrity, computeContentHash } from '../src/restore-memo.mjs';
import fs from 'node:fs';
import path from 'node:path';

function deny(res, status, reason, message) {
  return res.status(status).json({ error: 'restore_denied', reason, message });
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
    const backupSource = body.backup ?? candidate;

    // 사본에 기대되는 hash가 없으면 content에서 계산하여 안전하게 비교
    const expectedHash = backupSource.contentHash
      ?? backupSource.hash
      ?? computeContentHash(backupSource.content ?? backupSource.body ?? '');

    const targetVerification = verifyBackupIntegrity(
      {
        id: candidate.id,
        owner_id: candidate.owner_id ?? verifiedUserId,
        title: candidate.title ?? backupSource.title,
        content: candidate.content ?? candidate.body ?? backupSource.content ?? backupSource.body,
        contentHash: candidate.contentHash ?? candidate.hash ?? expectedHash,
      },
      {
        id: backupSource.id ?? candidate.id,
        owner_id: backupSource.owner_id ?? candidate.owner_id ?? verifiedUserId,
        title: backupSource.title ?? candidate.title,
        content: backupSource.content ?? backupSource.body ?? candidate.content ?? candidate.body,
        contentHash: expectedHash,
      },
      verifiedUserId
    );

    if (!targetVerification.valid) {
      return deny(res, 400, targetVerification.reason, '사본과의 ID·소유자·내용 해시 대조에 실패했습니다.');
    }

    // 다른 메모 및 감사 기록은 보존하며 지정한 단 1건만 복원(upsert)
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

    return res.status(200).json({
      status: 'restored',
      restoredCount: 1,
      id: targetVerification.verifiedId,
      resourceId: targetVerification.resourceId,
      owner_id: targetVerification.ownerId,
      contentHash: targetVerification.contentHash,
    });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
