import { createLoginVerifier } from '../../src/verify-login.mjs';
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return res.status(500).json({ error: "서버 환경변수 오류" });

  try {
    const configPath = path.join(process.cwd(), 'aleph.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: SUPABASE_SECRET_KEY });
    
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "토큰이 없습니다." });
    
    const user = await verifyLogin(authHeader);
    if (!user) return res.status(403).json({ error: "인증 실패" });

    // URL에서 :id 파라미터 추출
    const { id } = req.query;

    // 1. [단건 GET] - 소유자 확인 안 함
    if (req.method === 'GET') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}&select=id,title,content`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      const data = await response.json();
      
      if (!data || data.length === 0) return res.status(404).json({ error: "자료를 찾을 수 없습니다 (404)." });
      
      const note = { id: data[0].id, title: data[0].title, body: data[0].content };
      return res.status(200).json(note);
    }

    // 2. [수정 PUT] - 소유자 확인 안 함 (고의적 취약점)
    if (req.method === 'PUT') {
      const { title, body } = req.body;
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}`, {
        method: 'PATCH',
        headers: { 
          'apikey': SUPABASE_SECRET_KEY, 
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify({ title, content: body })
      });
      if (!response.ok) throw new Error(await response.text());
      return res.status(200).json({ id });
    }

    // 3. [삭제 DELETE] - 소유자 확인 안 함 (고의적 취약점)
    if (req.method === 'DELETE') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}`, {
        method: 'DELETE',
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      if (!response.ok) throw new Error(await response.text());
      return res.status(200).json({ id });
    }

    return res.status(405).json({ error: "허용되지 않는 메서드입니다." });
  } catch (error) {
    res.status(500).json({ error: "서버 에러: " + (error.message || error) });
  }
}