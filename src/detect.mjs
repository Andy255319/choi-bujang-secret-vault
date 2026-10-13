// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 입력은 반 엔진이 검증한 사건이어야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  for (const event of events) {
    if (event?.method !== 'GET'
        || typeof event.identity?.sub !== 'string'
        || !event.identity.sub
        || typeof event.at !== 'string') continue;

    const timestamp = Date.parse(event.at);
    if (!Number.isFinite(timestamp)) continue;

    const reads = readsBySubject.get(event.identity.sub) ?? [];
    reads.push(timestamp);
    readsBySubject.set(event.identity.sub, reads);
  }

  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);
    let firstInWindow = 0;
    for (let lastInWindow = 0; lastInWindow < timestamps.length; lastInWindow += 1) {
      while (timestamps[lastInWindow] - timestamps[firstInWindow] > WINDOW_MS) {
        firstInWindow += 1;
      }
      if (lastInWindow - firstInWindow + 1 > LIMIT) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
      }
    }
  }

  return { action: 'observe' };
}
