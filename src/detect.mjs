// 9단계 로컬 연습용 탐지기입니다. 운영 사건 전달이나 회수 집행을 하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;

// 계약(docs/DETECT_EVENTS.md)에 명시된 at, method, identity.sub 세 값만 읽습니다.
// 메모 내용, 토큰, 실명, 기기, 네트워크, 지역 등 추가 필드는 복사·저장·판정에 쓰지 않습니다.
function readVirtualEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;

  const at = event.at;
  const method = event.method;
  const subject = event.identity?.sub;

  if (typeof at !== 'string' || typeof method !== 'string' || typeof subject !== 'string' || !subject.trim()) {
    return null;
  }

  return {
    at,
    method: method.trim().toUpperCase(),
    subject: subject.trim(),
  };
}

export function detect(events) {
  // 배열이 아닌 단건 객체가 전달된 경우 단건 배열로 포용
  const eventList = Array.isArray(events)
    ? events
    : (events && typeof events === 'object' ? [events] : null);

  if (!eventList) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  for (const event of eventList) {
    const input = readVirtualEvent(event);
    if (!input || input.method !== 'GET') continue;

    const timestamp = Date.parse(input.at);
    if (!Number.isFinite(timestamp)) continue;

    const reads = readsBySubject.get(input.subject) ?? [];
    reads.push(timestamp);
    readsBySubject.set(input.subject, reads);
  }

  let burstCandidate = null;

  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);
    let firstInWindow = 0;
    for (let lastInWindow = 0; lastInWindow < timestamps.length; lastInWindow += 1) {
      while (timestamps[lastInWindow] - timestamps[firstInWindow] > WINDOW_MS) {
        firstInWindow += 1;
      }
      const windowCount = lastInWindow - firstInWindow + 1;
      // 10분 구간 안 120건을 넘으면 의심으로 판단 (정확히 120건은 제외)
      if (windowCount > LIMIT) {
        burstCandidate ??= subject;
        break;
      }
    }
    if (burstCandidate) break;
  }

  if (burstCandidate) {
    // 기기 번호 등 다른 키를 덧붙이지 않고 정확히 세 키만 반환
    return {
      action: 'propose_revocation',
      reasonCode: 'burst_read',
      subject: burstCandidate,
    };
  }

  return { action: 'observe' };
}

export class Detector {
  constructor(options = {}) { this.options = options; }
  detect(...args) { return detect(...args); }
  evaluate(...args) { return detect(...args); }
}

detect.detect = detect;
detect.evaluate = (...args) => detect(...args);

export default detect;