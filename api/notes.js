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

    // 모듈 방식(default/named) 차이로 인한 서버 크래시를 막기 위해 동적으로 불러옵니다.
    const authModule = await import('../src/verify-login.mjs');
    const verifyLogin = authModule.verifyLogin || authModule.default;

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
    // 서버가 뻗지 않고 확실하게 에러 사유를 브라우저로 보냅니다.
    console.error("API 내부 에러:", error);
    res.status(500).json({ error: "서버 내부 에러: " + (error.message || error) });
  }
}
