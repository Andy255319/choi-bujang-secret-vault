import { verifyLogin } from '../src/verify-login.mjs';

export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: "서버 환경변수(URL 또는 비밀키)가 없습니다." });
  }

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "토큰이 없습니다." });
    }

    const token = authHeader.replace('Bearer ', '');

    // 제공된 도우미 함수로 토큰 검증
    const isValid = await verifyLogin(token);
    if (!isValid) {
      return res.status(403).json({ error: "인증 검사에 실패했습니다." });
    }

    const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=title,content`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      }
    });

    if (!response.ok) {
      throw new Error("Supabase 데이터베이스 조회 실패");
    }

    const data = await response.json();
    res.status(200).json({ notes: data });

  } catch (error) {
    console.error("API 내부 에러:", error);
    res.status(500).json({ error: "서버 내부 에러: " + (error.message || error) });
  }
}
