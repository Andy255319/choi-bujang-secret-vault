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

test('확인된 가상 기기의 다량 조회만 한 기기 대상·이유를 명시한 제안을 낸다', () => {
  const result = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index, {
    virtualDevice: confirmedDevice,
  })));
  assert.deepEqual(result, {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: 'learner_fixture',
    target: expectedTarget,
  });
  const output = JSON.stringify(result);
  for (const marker of PRIVATE_MARKERS) assert.equal(output.includes(marker), false);
  assert.equal(output.includes('fixture-device-not-in-contract'), false);
});

test('비정상 네트워크와 확인 기기의 다량 조회가 함께 있을 때 복합 사유와 동일 대상만 제안한다', () => {
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
});

test('확인된 단일 가상 기기가 없는 다량 조회에는 회수 제안을 내지 않는다', () => {
  const missing = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index)));
  const unverified = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index, {
    virtualDevice: { id: 'fixture-device-01', verified: false },
  })));
  const otherDevice = detect(Array.from({ length: 121 }, (_, index) => virtualRead(index, {
    virtualDevice: { id: 'another-fixture-device', verified: true },
  })));
  assert.deepEqual(missing, { action: 'observe' });
  assert.deepEqual(unverified, { action: 'observe' });
  assert.deepEqual(otherDevice, { action: 'observe' });
});

test('비정상 네트워크만 있거나 지역 정보만 있으면 회수 제안을 내지 않는다', () => {
  const unusualOnly = detect(Array.from({ length: 30 }, (_, index) => virtualRead(index, {
    networkStatus: 'unusual', virtualDevice: confirmedDevice,
  })));
  const regionOnly = detect(Array.from({ length: 30 }, (_, index) => virtualRead(index, {
    region: 'fixture-new-region',
  })));
  assert.deepEqual(unusualOnly, { action: 'observe' });
  assert.deepEqual(regionOnly, { action: 'observe' });
});

test('탐지기는 계약 밖의 민감한 추가 필드를 읽지 않는다', () => {
  const event = {
    at: new Date(START).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture' },
  };
  for (const key of ['deviceId', 'memoContent', 'token', 'realName', 'decision', 'region']) {
    Object.defineProperty(event, key, {
      enumerable: true,
      get() { throw new Error(`unexpected_field_read:${key}`); },
    });
  }
  assert.deepEqual(detect([event]), { action: 'observe' });
});
