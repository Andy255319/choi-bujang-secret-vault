import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const suspiciousFallback = response => {
  assert.equal(response.decision, 'step_up');
  assert.equal(response.reasonCode, 'step_up_required');
};

test('클라이언트가 덧붙인 접속 헤더는 신뢰 접속 정보가 되지 않는다', async () => {
  const { normal } = fixtureRequests();
  const response = await decide({
    ...normal,
    headers: {
      'x-forwarded-for': '198.51.100.24',
      'x-region': 'local',
      'x-network': 'usual',
      'x-hour': '14',
    },
  });
  suspiciousFallback(response);
});

test('출처가 none 또는 불명확하면 정상값처럼 처리하지 않는다', async () => {
  const { normal } = fixtureRequests();
  for (const source of ['none', 'unknown', 'client_header']) {
    const response = await decide({
      ...normal,
      signals: { ...normal.signals, source },
    });
    suspiciousFallback(response);
  }
});

test('지역·시각·네트워크·행동 정보가 빠지면 추가 확인을 요구한다', async () => {
  const { normal } = fixtureRequests();
  const inputs = [
    { ...normal, signals: { ...normal.signals, region: undefined } },
    { ...normal, signals: { ...normal.signals, hour: undefined } },
    { ...normal, signals: { ...normal.signals, network: undefined } },
    { ...normal, recentEvents: undefined },
  ];
  for (const request of inputs) suspiciousFallback(await decide(request));
});

test('정상 사건은 허용하고 복합 이상 대량 읽기는 사유를 남겨 추가 확인한다', async () => {
  const { normal, suspicious } = fixtureRequests();
  const ordinary = await decide(normal);
  assert.equal(ordinary.decision, 'allow');

  const unusual = await decide(suspicious);
  assert.equal(unusual.decision, 'step_up');
  assert.equal(unusual.reasonCode, 'step_up_required');
  assert.ok(unusual.ruleIds.includes('unusual_bulk_read_step_up'));
});

test('지역 하나만으로 영구 차단하지 않는다', async () => {
  const { normal } = fixtureRequests();
  const response = await decide({
    ...normal,
    signals: { ...normal.signals, region: 'foreign' },
  });
  assert.notEqual(response.decision, 'deny');
  assert.equal(response.reasonCode, 'step_up_required');
  assert.ok(response.ruleIds.includes('step_up_required'));
  assert.ok(!response.ruleIds.includes('unusual_bulk_read_step_up'));
});

test('기기 등록 여부 검사는 새 복합 규칙보다 먼저 유지된다', async () => {
  const { suspicious } = fixtureRequests();
  const response = await decide({ ...suspicious, deviceRegistered: false });
  assert.equal(response.decision, 'deny');
  assert.equal(response.reasonCode, 'device_not_registered');
  assert.deepEqual(response.ruleIds, ['device_registered']);
});
