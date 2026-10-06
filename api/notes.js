export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: "서버 설정 오류" });
  }

  try {
    // Supabase의 notes 테이블에서 가상 메모를 가져옵니다.
    const response = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=title,content`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      }
    });

    const data = await response.json();
    
    // 데이터만 묶어서 브라우저로 응답합니다.
    res.status(200).json({ notes: data });
  } catch (error) {
    res.status(500).json({ error: "데이터 조회 실패" });
  }
}
