import { createLoginVerifier } from '../src/verify-login.mjs';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

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

    // 1. [목록 GET] - 로그인한 사용자의 메모 배열 반환
    if (req.method === 'GET') {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=id,title,content&owner_id=eq.${user.userId}`, {
        headers: { 'apikey': SUPABASE_SECRET_KEY, 'Authorization': `Bearer ${SUPABASE_SECRET_KEY}` }
      });
      const data = await response.json();
      
      // DB의 content를 API 응답 규격인 body로 매핑
      const mappedData = data.map(n => ({ id: n.id, title: n.title, body: n.content }));
      return res.status(200).json({ notes: mappedData });
    }

    // 2. [생성 POST] - 전달된 body와 자동 생성된 id, 소유자 id를 저장
    if (req.method === 'POST') {
      const { id = crypto.randomUUID(), title, body } = req.body;
      const payload = { id, title, content: body, owner_id: user.userId };

      const response = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
        method: 'POST',
        headers: { 
          'apikey': SUPABASE_SECRET_KEY, 
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) throw new Error(await response.text());
      return res.status(200).json({ id });
    }

    return res.status(405).json({ error: "허용되지 않는 메서드입니다." });
  } catch (error) {
    res.status(500).json({ error: "서버 에러: " + (error.message || error) });
  }
}
