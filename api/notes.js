import { createLoginVerifier } from '../src/verify-login.mjs';
import { createResourceId, parseMemoResourceId } from '../src/resource-id.mjs';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function deny(res, status, reason) {
  return res.status(status).json({ error: 'access_denied', reason });
}

export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return res.status(500).json({ error: 'server_configuration_error' });

  try {
    const configPath = path.join(process.cwd(), 'aleph.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: SUPABASE_SECRET_KEY });

    const authHeader = req.headers.authorization;
    if (!authHeader) return deny(res, 401, 'login_required');

    const user = await verifyLogin(authHeader);
    if (!user) return deny(res, 403, 'login_invalid');
    // Only the verified principal returned by the verifier is used. A body role is ignored.
    if (user.kind !== 'student' || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
      return deny(res, 403, 'verified_student_required');
    }
    const ownerId = user.userId;

    // [목록 GET] DB의 저장 소유자를 검증된 사용자와 대조한 메모만 반환합니다.
    if (req.method === 'GET') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=id,title,content,owner_id&owner_id=eq.${encodeURIComponent(ownerId)}`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      if (!response.ok) return res.status(502).json({ error: 'storage_unavailable' });
      const data = await response.json();
      if (!Array.isArray(data)) return res.status(502).json({ error: 'storage_response_invalid' });

      const mappedData = data.filter(n => n?.owner_id === ownerId).map(n => ({
        id: n.id,
        resourceId: createResourceId('memo', String(n.id)),
        title: n.title,
        body: n.content
      }));
      return res.status(200).json({ notes: mappedData });
    }

    // [생성 POST] 소유자 ID는 검증 결과에서만 설정하고 본문 role/owner_id는 사용하지 않습니다.
    if (req.method === 'POST') {
      const { id: suppliedId, title, body } = req.body ?? {};
      const parsedId = suppliedId === undefined ? null : parseMemoResourceId(String(suppliedId));
      if (suppliedId !== undefined && (!parsedId || parsedId.type !== 'memo')) {
        return res.status(400).json({ error: 'invalid_memo_resource_id' });
      }
      const id = parsedId?.id ?? crypto.randomUUID();
      const payload = { id, title, content: body, owner_id: ownerId };

      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) return res.status(502).json({ error: 'storage_write_failed' });
      return res.status(200).json({ id, resourceId: createResourceId('memo', String(id)) });
    }

    return res.status(405).json({ error: 'method_not_allowed' });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
