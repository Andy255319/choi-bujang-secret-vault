# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 로컬 가상 조회 사건을 전달합니다. 각 사건은 다음 세 필수 값과 선택 신호를 가집니다.

```js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  identity: { sub: 'learner_fixture' },
  networkStatus: 'unusual',
  virtualDevice: { id: 'fixture-device-01', verified: true }
}
```

`networkStatus`는 엔진이 검증한 분류인 `'usual'` 또는 `'unusual'`일 때만 사용합니다. 이 값이 없거나 다른 값이면 네트워크 상태는 알 수 없는 것으로 취급하며 정상으로 추정하지 않습니다. 지역은 이 탐지 규칙의 신호가 아닙니다.

회수 제안의 대상은 계약에 정한 단 하나의 가상 기기 `fixture-device-01`뿐입니다. 사건에 `virtualDevice`가 있고 `verified: true`이며 ID가 정확히 일치할 때만 확인된 가상 기기로 취급합니다. 이 정보가 없거나 확인되지 않았거나 다른 기기 ID라면 회수 제안을 만들지 않습니다. 제안 결과에는 `target: { type: 'virtual_device', id: 'fixture-device-01' }`와 사유 코드가 들어갑니다. 이는 로컬 fixture 전용 표식이며 실제 기기나 운영 엔진의 검증을 나타내지 않습니다.

같은 `identity.sub`의 `GET` 사건이 어느 10분 구간에서든 **120건을 넘을 때**, 해당 구간이 위 확인된 가상 기기 한 대로만 구성되어 있으면 기존 다량 조회 규칙이 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '해당 sub', target: { type: 'virtual_device', id: 'fixture-device-01' } }`를 돌려줍니다. 정확히 120건은 대상이 아니며, 다른 사용자의 사건을 합산하거나 10분 밖의 사건을 같은 묶음으로 세지 않습니다.

새 복합 규칙은 같은 사용자·같은 10분 구간에 120건 초과 조회와 명시적인 `networkStatus: 'unusual'` 사건이 함께 있을 때만 `reasonCode: 'unusual_network_burst_read'`로 표시합니다. 비정상 네트워크만 있거나 지역 정보만으로는 이 복합 규칙을 발동하지 않습니다. 기존 다량 조회 규칙은 확인된 가상 기기 한 대에 한정해 보존됩니다.

이 사건 모양은 **로컬 연습용**입니다. 브라우저가 보낸 사용자 번호나 검증되지 않은 신호를 신원·접속 상태로 취급하지 않습니다. 운영 반 엔진이 검증한 사건을 전달하고 회수 제안을 집행하는 경로는 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다. 실제 기기 권한 변경이나 회수 API 호출은 하지 않으며, 실제 회수 여부와 시간은 심판이 확인합니다.
