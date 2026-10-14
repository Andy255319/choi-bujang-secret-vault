import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const PRIVATE_MARKERS = ['PRIVATE_MEMO_MARKER', 'PRIVATE_TOKEN_MARKER', 'PRIVATE_NAME_MARKER'];
const confirmedDevice = { id: 'fixture-device-01', verified: true };
const expectedTarget = { type: 'virtual_device', id: 'fixture-device-01' };

function virtualRead(index, extra = {}) {
  return {
    at: new Date(START + index * 1000).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture', realName: PRIVATE_MARKERS[2] },
    memoContent: PRIVATE_MARKERS[0],
    token: PRIVATE_MARKERS[1],
    decision: 'allow',
    ...extra,
  };
}

test('정상 가상 사건과 단순 다량 조회는 관찰하며 민감 필드를 출력하지 않는다', () => {
  const normal = detect(Array.from({ length: 30 }, (_, index) => virtualRead(index, { virtualDevice: confirmedDevice })));
  const burstOnly = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index, { virtualDevice: confirmedDevice })));
  assert.deepEqual(normal, { action: 'observe' });
  assert.deepEqual(burstOnly, { action: 'observe' });
  const output = JSON.stringify({ normal, burstOnly });
  for (const marker of PRIVATE_MARKERS) assert.equal(output.includes(marker), false);
});

test('비정상 네트워크와 확인 기기의 다량 조회가 함께 있을 때만 회수 제안을 낸다', () => {
  const result = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index, {
    networkStatus: 'unusual',
    virtualDevice: confirmedDevice,
  })));
  assert.deepEqual(result, {
    action: 'propose_revocation',
    reasonCode: 'unusual_network_burst_read',
    subject: 'learner_fixture',
    target: expectedTarget,
  });
  const output = JSON.stringify(result);
  for (const marker of PRIVATE_MARKERS) assert.equal(output.includes(marker), false);
});

test('비정상 네트워크만 있거나 지역 정보만 있으면 회수 제안을 내지 않는다', () => {
  const unusualOnly = detect(Array.from({ length: 30 }, (_, index) => virtualRead(index, {
    networkStatus: 'unusual',
    virtualDevice: confirmedDevice,
  })));
  const regionBurst = detect(Array.from({ length: 121 }, (_, index