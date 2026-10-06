import { createLoginVerifier } from '../src/verify-login.mjs';
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: "서버 환경변수 오류" });
  }

  try {
    // 1. aleph.config.json 설정 파일 읽어오기
    const configPath = path.join(process.cwd(), 'aleph.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // 2. 도우미 생성 함수로 진짜 토큰 검사기(verifyLogin) 만들기
    const verifyLogin = createLoginVerifier({
      config: config,
      supabaseSecretKey: SUPABASE_SECRET_KEY
    });

    // 3. 토큰 추출 및 검사 (도우미 규칙에 따라 'Bearer ' 글자까지 통째로 넘김)
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "토큰이 없습니다." });
    }

    const user = await verifyLogin(authHeader);
    if (!user) {
      return res.status(403).json({ error: "인증 검사에 실패했습니다. 권한이 없습니다." });
    }

    // 4. 통과 시 데이터베이스 조회
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
    res.status(200).json({ notes: data });
  } catch (error) {
    console.error("API 내부 에러:", error);
    res.status(500).json({ error: "서버 내부 에러: " + (error.message || error) });
  }
}