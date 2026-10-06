import { verifyLogin } from '../src/verify-login.mjs';

export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: "서버 환경변수 설정 오류" });
  }

  try {
    // 1. 요청 헤더에서 인증 토큰(Authorization) 추출
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "토큰이 없습니다." });
    }

    const token = authHeader.replace('Bearer ', '');

    // 2. 제공된 도우미를 통해 토큰 검증 (브라우저 정보는 믿지 않고 토큰 자체만 검사)
    const isValid = await verifyLogin(token);
    if (!isValid) {
      return res.status(403).json({ error: "인증 검사에 실패했습니다." });
    }

    // 3. 검증 통과 시에만 서버의 비밀 키를 사용해 Supabase에서 메모 데이터 조회
    const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=title,content`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      }
    });

    if (!response.ok) {
      throw new Error("데이터베이스 조회 실패");
    }

    const data = await response.json();
    
    // 4. 데이터 반환
    res.status(200).json({ notes: data });
  } catch (error) {
    res.status(500).json({ error: "데이터 조회 실패" });
  }
}
