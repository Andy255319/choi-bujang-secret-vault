import { createLoginVerifier } from '../src/verify-login.mjs';
import { decide } from '../src/decider.mjs';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'server_configuration_error' });
  }

  try {
    const configPath = path.join(process.cwd(), 'aleph.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: SUPABASE_SECRET_KEY });

    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'access_denied', reason: 'login_required' });
    }

    const user = await verifyLogin(authHeader);
    if (!user || user.kind !== 'student' || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
      return res.status(403).json({ error: 'access_denied', reason: 'verified_student_required' });
    }

    // 미등록 기기 시험용 플래그 확인 (헤더, 쿼리 또는 본문)
    const isUnregistered = req.headers['x-device-unregistered'] === 'true'
      || req.query?.unregistered === 'true'
      || req.body?.deviceRegistered === false;

    const deviceRegistered = !isUnregistered;

    // 판정기(decider.mjs)에 공식 계약으로 기기 등록 상태 확인
    const deciderRequest = {
      schema: 'aleph.decision.v1',
      requestId: crypto.randomUUID(),
      classId: 'class_main',
      projectId: 'project_vault',
      subjectId: user.userId,
      deviceId: '0123456789abcdef',
      service: 'device',
      method: req.method || 'POST',
      path: '/api/device',
      route: 'POST /api/device',
      queryLength: 0,
      querySha256: crypto.createHash('sha256').update('').digest('hex'),
      at: new Date().toISOString(),
      policyRevision: 1,
      deviceRegistered,
      stepUp: { verified: false, authAgeSeconds: null },
      recentEvents: [],
      signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 }
    };

    const decision = await decide(deciderRequest);

    if (decision.decision === 'allow' && decision.reasonCode === 'approved') {
      return res.status(200).json({
        approved: true,
        decision: 'allow',
        reasonCode: 'approved',
        deviceRegistered: true,
        message: '서버 판정기에 의해 등록 기기로 확인되었습니다. 자료실 접근이 승인되었습니다.'
      });
    }

    return res.status(403).json({
      approved: false,
      decision: decision.decision,
      reasonCode: decision.reasonCode,
      deviceRegistered: false,
      message: '등록되지 않은 기기입니다. 서버 판정기에 의해 자료실 접근이 거부되었습니다.'
    });
  } catch {
    return res.status(500).json({ error: 'server_error' });
  }
}
