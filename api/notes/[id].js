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

    const { id } = req.query;

    // [단건 GET] - ID와 소유자가 모두 일치해야만 반환
    if (req.method === 'GET') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}&owner_id=eq.${user.userId}&select=id,title,content`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      const data = await response.json();
      
      if (!data || data.length === 0) return res.status(404).json({ error: "자료를 찾을 수 없거나 접근 권한이 없습니다." });
      
      const note = { id: data[0].id, title: data[0].title, body: data[0].content };
      return res.status(200).json(note);
    }

    // [수정 PUT] - 기존 행의 주인이 본인인지 확인(URL 쿼리) + 새 행의 주인도 본인으로 유지(body)
    if (req.method === 'PUT') {
      const { title, body } = req.body;
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}&owner_id=eq.${user.userId}`, {
        method: 'PATCH',
        headers: { 
          'apikey': SUPABASE_SECRET_KEY, 
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`, 
          'Content-Type': 'application/json',
          'Prefer': 'return=representation'
        },
        body: JSON.stringify({ title, content: body, owner_id: user.userId })
      });
      
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || "수정 실패");
      if (result.length === 0) return res.status(404).json({ error: "수정 권한이 없거나 자료가 없습니다." });
      
      return res.status(200).json({ id });
    }

    // [삭제 DELETE] - 주인이 일치할 때만 삭제 허용
    if (req.method === 'DELETE') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${id}&owner_id=eq.${user.userId}`, {
        method: 'DELETE',
        headers: { 
          'apikey': SUPABASE_SECRET_KEY, 
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Prefer': 'return=representation' 
        }
      });
      
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || "삭제 실패");
      if (result.length === 0) return res.status(404).json({ error: "삭제 권한이 없거나 자료가 없습니다." });
      
      return res.status(200).json({ id });
    }

    return res.status(405).json({ error: "허용되지 않는 메서드입니다." });
  } catch (error) {
    res.status(500).json({ error: "서버 에러: " + (error.message || error) });
  }
}