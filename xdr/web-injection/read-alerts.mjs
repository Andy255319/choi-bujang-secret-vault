import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);

/** 경보 원본에서 지정된 다섯 항목만 추려 반환합니다. */
export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('웹 주입 경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: alert.timestamp ?? null,
    sourceAddress: alert.data?.srcip ?? null,
    account: alert.data?.srcuser ?? null,
    ruleLevel: alert.rule?.level ?? null,
    description: alert.rule?.description ?? null,
  }));
}

/** 각 경보를 한 줄의 JSON으로 바꿉니다. 다른 필드는 출력하지 않습니다. */
export function toAlertLines(alerts) {
  return alerts.map((alert) => JSON.stringify({
    timestamp: alert.timestamp,
    sourceAddress: alert.sourceAddress,
    account: alert.account,
    ruleLevel: alert.ruleLevel,
    description: alert.description,
  }));
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  try {
    const alerts = await readAlerts();
    for (const line of toAlertLines(alerts)) console.log(line);
  } catch {
    // 오류 출력에 경보 원문이나 그 안의 비밀값을 포함하지 않습니다.
    console.error('경보를 읽을 수 없습니다.');
    process.exitCode = 1;
  }
}
