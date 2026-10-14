import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const PRIVATE_MARKERS = ['PRIVATE_MEMO_MARKER', 'PRIVATE_TOKEN_MARKER', 'PRIVATE_NAME_MARKER'];

function virtualRead(index, extra = {}) {
  return {
    at: new Date(START + index * 1000).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture', realName: PRIVATE_MARKERS[2] },
    memoContent: PRIVATE_MARKERS[0],
    token: PRIVATE_MARKERS[1],
    deviceId: 'fixture-device-not-in-contract',
    decision: 'allow',
    ...extra,
  };
}

test('정상 가상 사건은 관찰하며 회수 제안을 내지 않고 민감 필드를 출력하지 않는다', () => {
  const result = detect(Array.from({ length: 30 }, (_, index) => virtualRead(index)));
  assert.deepEqual(result, { action: 'observe' });
  const output = JSON.stringify(result);
  for (const marker of PRIVATE_MARKERS) assert.equal(output.includes(marker), false);
  assert.equal(output.includes('fixture-device-not-in-contract'), false);
});

test('10분 안 120건 조회의 경계값은 정상으로 관찰한다', () => {
  const result = detect(Array.from({ length: 120 }, (_, index) => virtualRead(index)));
  assert.deepEqual(result, { action: 'observe' });
});

test('10분 안 121건 폭주 조회는 정확히 3개 키만 돌려준다', () => {
  const result = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index)));
  assert.deepEqual(result, {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: 'learner_fixture',
  });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
  const output = JSON.stringify(result);
  for (const marker of PRIVATE_MARKERS) assert.equal(output.includes(marker), false);
  assert.equal(output.includes('fixture-device-not-in-contract'), false);
});

test('탐지기는 계약 밖의 민감한 추가 필드를 읽지 않는다', () => {
  const event = {
    at: new Date(START).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture' },
  };
  for (const key of ['deviceId', 'memoContent', 'token', 'realName', 'decision', 'region', 'networkStatus', 'virtualDevice']) {
    Object.defineProperty(event, key, {
      enumerable: true,
      get() { throw new Error(`unexpected_field_read:${key}`); },
    });
  }
  assert.deepEqual(detect([event]), { action: 'observe' });
});
