import { verifyLogin } from '../src/verify-login.mjs';

export default async function handler(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "토큰이 없습니다." });
  }
  const token = authHeader.replace('Bearer ', '');
  const isValid = await verifyLogin(token);
  if (!isValid) {
    return res.status(403).json({ error: "권한이 없습니다." });
  }
  // 이후 기존 데이터 조회 로직...
}

  try {
    // 1. 요청 헤더에서 인증 토큰(Authorization) 추출
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "토큰이 없습니다." });
    }

    const token = authHeader.replace('Bearer ', '');

    // 2. 제공된 도우미(src/verify-login.mjs)를 통해 토큰 검증
    const isValid = await verifyLogin(token);
    if (!isValid) {
      return res.status(403).json({ error: "인증 검사 실패" });
    }

    // 3. 검증 통과 시에만 Supabase에서 메모 데이터 조회
    const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=title,content`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      }
    });

    const data = await response.json();
    res.status(200).json({ notes: data });
  } catch (error) {
    res.status(500).json({ error: "데이터 조회 실패" });
  }
}
