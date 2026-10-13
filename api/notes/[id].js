import { createLoginVerifier } from '../../src/verify-login.mjs';
import { createResourceId, parseMemoResourceId } from '../../src/resource-id.mjs';
import fs from 'fs';
import path from 'path';

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
    if (user.kind !== 'student' || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
      return deny(res, 403, 'verified_student_required');
    }
    const ownerId = user.userId;

    const parsedId = parseMemoResourceId(String(req.query.id ?? ''));
    if (!parsedId || parsedId.type !== 'memo') {
      return deny(res, 400, 'invalid_memo_resource_id');
    }
    const id = parsedId.id;
    const encodedId = encodeURIComponent(id);
    const resourceId = createResourceId('memo', id);

    // Only rows whose stored owner_id matches the verified principal are eligible.
    if (req.method === 'GET') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}&owner_id=eq.${encodeURIComponent(ownerId)}&select=id,title,content`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      if (!response.ok) return res.status(502).json({ error: 'storage_unavailable' });
      const data = await response.json();

      if (!Array.isArray(data)) return res.status(502).json({ error: 'storage_response_invalid' });
      if (data.length === 0) return deny(res, 404, 'not_found_or_not_owner');

      const note = { id: data[0].id, resourceId: createResourceId('memo', String(data[0].id)), title: data[0].title, body: data[0].content };
      return res.status(200).json(note);
    }

    if (req.method === 'PUT') {
      const { title, body } = req.body ?? {};
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}&owner_id=eq.${encodeURIComponent(ownerId)}`, {
        method: 'PATCH',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation'
        },
        // Client-supplied role/owner fields are deliberately never forwarded.
        body: JSON.stringify({ title, content: body, owner_id: ownerId })
      });

      if (!response.ok) return res.status(502).json({ error: 'storage_write_failed' });
      const result = await response.json();
      if (!Array.isArray(result)) return res.status(502).json({ error: 'storage_response_invalid' });
      if (result.length === 0) return deny(res, 404, 'not_found_or_not_owner');

      return res.status(200).json({ id, resourceId });
    }

    if (req.method === 'DELETE') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodedId}&owner_id=eq.${encodeURIComponent(ownerId)}`, {
        method: 'DELETE',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Prefer': 'return=representation'
        }
      });

      if (!response.ok) return res.status(502).json({ error: 'storage_write_failed' });
      const result = await response.json();
      if (!Array.isArray(result)) return res.status(502).json({ error: 'storage_response_invalid' });
      if (result.length === 0) return deny(res, 404, 'not_found_or_not_owner');

      return res.status(200).json({ id, resourceId });
    }

    return res.status(405).json({ error: 'method_not_allowed' });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
