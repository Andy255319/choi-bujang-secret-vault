# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

약점: 현재 서버 API 함수(/api/notes)는 인증 절차가 없어 누구에게나 열려 있는 공개 주소입니다.

### 2단계: 자료를 코드 밖으로 옮깁니다 (결과 및 약점 기록)

* **검색 결과 확인**: 최신 GitHub 커밋과 Vercel 배포 파일의 `/data.json`을 확인한 결과, 가상 메모 문장이 모두 제거되어 빈 배열로 정상 처리되었음을 확인했습니다.
* **과거 노출 상태**: 최신 코드에서는 자료가 분리되었으나, 과거의 공개 커밋 기록과 예전 Vercel 배포 주소에는 기존 데이터가 그대로 남아있으므로 과거 데이터 노출 위험이 완전히 해소된 것은 아닙니다.
* **남은 약점 (공개 API)**: 생성된 서버 API 함수(`/api/notes`)는 브라우저나 응답 로그에 비밀 키를 노출하지는 않지만, 현재 아무런 인증 방어막이 없습니다. 따라서 누구든 해당 공개 주소로 접속하면 서버를 통해 데이터베이스의 메모를 읽을 수 있는 상태입니다.

### 3단계: 인증 토큰 검증 및 보안 헤더 설정
* `verify-login.mjs`를 통해 Supabase JWT 인증을 서버에서 직접 검증하도록 구현했습니다.
* `vercel.json`의 headers 설정으로 `X-Content-Type-Options: nosniff` 보안 헤더를 추가했습니다.

### 4단계: 로그인해도 내 자료만 보이게 합니다 (IDOR 방어 및 RLS 적용)
* **API 레벨 검증**: `api/notes.js` 및 `api/notes/[id].js`에서 클라이언트가 전달한 `owner_id`를 신뢰하지 않고, 검증된 토큰의 `user.userId`와 데이터베이스의 `owner_id`를 대조하여 본인 메모에 대해서만 조회·추가·수정·삭제를 허용하도록 구현했습니다.
* **DB 레벨 방어 (RLS 및 최소 권한)**: Supabase PostgreSQL에서 `anon` 역할의 권한을 회수하고 `authenticated` 역할에만 최소 CRUD 권한을 부여했으며, `auth.uid() = owner_id` 조건의 RLS 정책을 적용했습니다.
* **100점 가산 조건 점검**:
  1. 비로그인 요청 시 401/403 JSON 에러 응답 보장
  2. `/aleph.json` 빌드 산출물 보존 확인
  3. 첫 화면 응답 보안 헤더(`X-Content-Type-Options: nosniff`) 적용 완료

### 5단계: 자료 요청을 서버 한곳으로 모읍니다 (직접 접근 차단 및 단일 관문 적용)
* **직접 권한 회수**: Supabase PostgreSQL에서 `notes` 테이블에 대한 `PUBLIC`, `anon`, `authenticated`의 모든 직접 권한을 `REVOKE ALL`로 회수하여, 공개 키(`anon`) 및 토큰을 통한 Data API 직접 호출 통로를 원천 차단했습니다.
* **단일 관문 유지**: 모든 메모 읽기·추가·수정·삭제는 Vercel 서버 함수(`api/notes.js`, `api/notes/[id].js`)를 통해서만 실행되며, 서버 환경변수(`service_role`) 기반 로그인·소유자 검사 로직을 유지했습니다.
* **설정 동기화**: `aleph.config.json`의 `originalApiUrl`에 쿼리 파라미터가 없는 원본 REST 저장소 주소(`https://aqeglcbdaaaixmznyavk.supabase.co/rest/v1/notes`)를 등록했습니다.
* **100점 가산 조건 점검**:
  1. `/aleph.json`의 `allowedRoutes`에 API 허용 경로 5개 등록 확인
  2. `vercel.json`의 첫 화면 응답 보안 헤더(`X-Content-Type-Options: nosniff`) 유지
  3. 클라이언트 화면 코드 내 Supabase 공개 키(`anon` / `sb_publishable_...`) 제거 및 키의 서버 함수 격리 확인

### 6단계: 등록한 기기만 자료실에 들어옵니다

저장소 루트에서 다음 명령을 실행해 판정기 로컬 연습을 합니다. 별도 접속 프로그램 설치는 필요하지 않습니다.

```sh
npm run decider:test
```

출력에서 다음 두 결과를 확인하세요.

```text
통과 · 등록 기기의 정상 요청: allow (approved)
통과 · 미등록 기기의 가상 요청: deny (device_not_registered)
```

등록 기기의 정상 요청은 `allow`로 통과해야 합니다. 테스트가 만든 미등록 기기의 가상 요청은 `deny`이며 이유 코드 `device_not_registered`여야 합니다. 이 명령은 가상 요청을 이용한 로컬 연습일 뿐, 운영 반 엔진이나 심판의 판정 결과가 아닙니다. 미등록 기기 공격 판정은 심판이 맡으며, 이 연습은 실제 접속 차단이나 심판 통과 증거를 대신하지 않습니다.

### 7단계: 평소와 다른 접속은 다시 확인합니다

7단계에서 `aleph.config.json`을 7단계로 설정하고, `src/decider.mjs`에 야간(22:00~05:59)·처음 보는 네트워크·최근 5분간 20회 이상 읽기가 함께 들어온 가상 사건의 `step_up_required` 판정을 두었습니다. 지역 하나만으로 영구 차단하지 않고, 등록 기기 검사도 유지합니다.

저장소 루트에서 가상 사건을 확인하세요.

```sh
npm run fixture:7
npm run decider:test
```

정상 가상 사건은 `allow`, 복합 이상 가상 사건은 `step_up (step_up_required)`여야 합니다. `npm run decider:test`에는 가상 미등록 기기 거부와 확인 완료 표시가 있는 후속 요청의 허용 확인도 포함됩니다. 후속 요청은 fixture의 `stepUp.verified` 표시만 시험하며, 같은 로그인 사용자가 실제로 재인증했는지 입증하지 않습니다. 요청 계약에 같은 로그인으로 재인증한 시각을 확인할 정보가 없으므로 실제 재로그인·실제 자료 차단·운영 판정은 실행하지 않았습니다. 토큰 원문은 기록하지 않습니다.

### 8단계: 자료마다 갈 수 있는 구역을 나눕니다

8단계 작업 당시 `aleph.config.json`을 8단계로 설정했습니다. 현재 설정 단계는 9입니다. `src/resource-id.mjs`는 메모를 `memo:<ID>`로, 강사 공지를 `instructor-announcement:<ID>`로 구분하므로 두 종류의 자료 ID가 서로 섞이지 않습니다. 기존 메모 ID와 기존 주소 형식은 계속 처리되며, 공지 유형 ID를 메모 API에 전달하면 거부됩니다.

`api/notes.js`와 `api/notes/[id].js`는 요청 본문의 `role`을 권한 근거로 쓰지 않습니다. 로그인 검증 결과의 학생 ID와 DB에 저장된 `owner_id`를 다시 대조하고, 일치하지 않거나 자료가 없으면 `not_found_or_not_owner`로 응답합니다. 기존 중첩 API 경로도 같은 검사기를 사용합니다. 이 검사는 API 직접 요청에도 적용되며 화면 메뉴 변경은 하지 않았습니다.

현재 저장소에는 강사 공지의 실제 데이터 출처(API·DB 테이블)가 확인되지 않았으므로, 공지 내용을 가져오거나 강사 공유 권한을 새로 만든 것으로 간주하지 않습니다. 이 단계에서 확인할 수 있는 범위는 타입별 자원 ID 분리와 기존 메모 API의 소유자 검사입니다.

저장소 루트에서 관련 회귀 테스트를 실행하세요.

```sh
node --test test/resource-id.test.mjs test/api-owner-scope.test.mjs
```

정상 결과는 자원 ID의 타입 구분·기존 ID 호환 및 목록·단건·중첩 API의 소유자 검사 테스트 통과입니다. 이 로컬 테스트는 배포 API에 직접 요청한 실측이나 심판 판정이 아닙니다.

### 9단계: 도플갱어를 찾고 권한을 거둡니다

`aleph.config.json`의 현재 단계는 9입니다. `src/detect.mjs`는 `docs/DETECT_EVENTS.md` 계약에 정의된 가상 사건(`at`, `method`, `identity.sub`)만 읽으며, 같은 가명 사용자의 `GET` 조회가 어느 10분 구간에서든 120건을 넘으면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`를 제안합니다. 사건에 없는 네트워크·기기·지역 정보는 참조하지 않으며 기기 번호 등 다른 키를 덧붙이지 않습니다. 120건 이하, 느린 조회, 복수 사용자 사건은 `{ action: 'observe' }`로 관찰하며 정상 기기를 유지합니다.

저장소 루트에서 로컬 가상 사건을 확인하세요.

```sh
npm run detect:test
node --test test/detect-input.test.mjs
```

정상 결과는 탐지 연습 사례와 입력 테스트가 통과하고, 폭주 묶음에 한해 사유 코드와 주체만 포함된 제안을 내는 것입니다. 이 탐지기는 실제 회수 API를 호출하거나 기기 권한을 바꾸지 않습니다. 명령 통과는 운영 엔진의 사건 전달·실제 회수·심판 판정을 증명하지 않으며, 실제 회수 여부와 시간은 심판이 확인합니다.

제출 묶음은 저장소 상태가 깨끗하고 변경이 커밋된 뒤 `npm run bundle`로 만듭니다. 이 명령은 자체 점검 결과와 요약을 출력하며, 생성되는 `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 마세요. 자체 점검은 가상 요청 판정이지 심판이나 실제 접속 결과가 아닙니다.

### 10단계: 백업에서 자료실을 되살립니다

`aleph.config.json`의 현재 단계는 10이며, 복원 경로 `POST /api/restore`가 `restoreRoute` 및 허용 경로에 등록되어 있습니다.

* **만들기 1 (안전 정책 사본 차이 사전 확인)**: 침해 전에 검증한 안전 정책 사본(`src/policy-restore.mjs`)과 현재 시험 정책의 차이를 계산하여 복원할 대상 버전(`safe_policy_v1`)과 변경 범위(`changes.rulesToRestore`)를 실행 전에 보여 줍니다. 사본이 없거나 검증 실패 시 즉시 중단하며, 실제 운영 정책은 건드리지 않습니다.
* **만들기 2 (안전 정책 복원 절차 및 보존)**: 검증한 안전 정책 버전으로 시험 정책을 되돌리며, 실행 전에 바뀔 항목을 확인하게 합니다. 다른 서비스 규칙(감사 등)과 감사 이력은 철저히 보존되며, 시험 계정 B의 A 자료 요청은 거부되고 A 정상 요청은 유지됩니다.
* **만들기 3 (비공개 가상 메모 사본 단건 복원 POST 경로)**:
  - **서비스 및 경로**: 비공개 가상 메모 복원 서비스 `POST /api/restore` (`api/restore.js`)
  - **단건 무결성 대조**: 비공개 가상 메모 사본 파일(`data/backup-notes.json`)에서 원본을 실시간으로 다시 읽어와, 복구 대상 한 건의 ID(`00000000-0000-4000-8000-00000000000b`), 소유자(`owner_id: 00000000-0000-4000-8000-00000000000b`), 내용 해시(`contentHash: eef8755315bd87e7cdfa6c54ae226e96a57b0c6c839e0add4cd3a58ba8fb5e2f`)가 사본과 같은지 엄격히 대조합니다.
  - **사본 부재 및 변조 시 복원 중단**: 복원 대상 사본 또는 ID가 지정되지 않은 빈 본문 요청이나 사본이 존재하지 않는 경우 임의 대상의 기본값 복원을 수행하지 않고 즉시 멈추며(`400 backup_not_found`), 내용 해시가 사본과 다르거나 변조된 경우 복원을 즉시 중단합니다(`400 content_hash_mismatch`).
  - **실행 전 버전과 바뀔 항목 표시**: 복구 실행 전에 사본 버전(`backup_v1`)과 바뀔 항목(`changes`)을 확인하게 하며, 실제 운영 정책은 건드리지 않습니다.
  - **보존 원칙**: 다른 메모나 감사 기록(audit logs 등)은 일절 건드리지 않고 대상 단 1건만 검증된 사본 내용으로 안전하게 복원(PostgREST upsert 및 PATCH)합니다.
  - **시험 계정 B 확인**: 시험 계정 B의 가상 사본으로만 검증을 수행하여, ID·소유자·내용 해시가 사본과 정확히 일치하는 경우에만 복원 검증(`verified: true`)을 통과하고 변조된 메모는 사본 내용으로 갱신 완료합니다.

저장소 루트에서 복원 무결성 검증 테스트를 실행하세요.

```sh
node --test test/restore.test.mjs
```

정상 결과는 시험 계정 B의 사본 파일 재조회 통과, 사본 부재 및 대상 미지정 시 중단, 내용 해시·소유자·ID 불일치 시의 거부 확인, 정책 사본 차이 계산 및 복원 검증, B의 A 자료 요청 거부 통과(12건 통과)입니다.

### 복구 후 1~9단계 정상·금지 요청 재실행 순서 및 확인

자료실과 보안 정책이 복원된 후, 이전에 막던 요청이 다시 정상적으로 거부되고 인가된 요청만 허용되는지 단계별로 점검하는 순서입니다. 로컬 테스트 및 설정 대조 결과만 기록하며, 실제 배포 API 호출이나 운영 심판 판정 등 실행하지 않은 항목은 미실행으로 남깁니다.

1. **[1~2단계] 공개 가상 메모 분리 상태 확인**
   - **실행**: `node scripts/build-public.mjs --local`
   - **정상 결과 (허용)**: 정적 산출물 및 `data.json`에서 공개 메모 본문이 제거되어 빈 배열(`notes: []`)로 분리 유지.
   - **거부/남은 약점 (미실행/주의)**: 과거 배포 이력의 노출 위험은 남아있으며, 원격 배포 주소 직접 요청 실측은 미실행.

2. **[3~5단계] 토큰 인증 및 단일 관문(IDOR 방지) 검증**
   - **실행**: `node --test test/api-owner-scope.test.mjs`
   - **정상 결과 (허용)**: 검증된 학생 신원(`owner_id`)과 일치하는 본인 메모의 조회·작성 허용.
   - **거부되어야 할 결과 (거부)**:
     - 비로그인 요청 시 `401/403` 즉시 거부 (`login_required`, `login_invalid`).
     - 타인 계정의 메모 조회·수정·삭제 시도 시 `404 not_found_or_not_owner` 거부.
     - 클라이언트가 임의로 전송한 `role` 또는 `owner_id` 조작 요청 무시.
   - **미실행**: 실제 Supabase DB에 대한 비인가 원격 직접 쿼리 실측은 로컬 단위 테스트 범위 밖이므로 미실행.

3. **[6단계] 등록 기기 접근 판정 검증**
   - **실행**: `npm run decider:test`
   - **정상 결과 (허용)**: 등록 기기의 가상 요청 -> `allow (approved)`.
   - **거부되어야 할 결과 (거부)**: 미등록 기기의 가상 요청 -> `deny (device_not_registered)`.
   - **미실행**: 실제 단말기의 기기 인증서 검증 및 운영 엔진 판정은 미실행(가상 요청 연습).

4. **[7단계] 이상 접속 추가 확인(Step-up) 검증**
   - **실행**: `npm run fixture:7` 후 `npm run decider:test`
   - **정상 결과 (허용)**: 재인증 완료 표시가 있는 가상 후속 요청 -> `allow (approved)`.
   - **거부되어야 할 결과 (거부)**: 야간·처음 보는 네트워크·대량 조회가 결합된 이상 가상 요청 -> `step_up (step_up_required)`.
   - **미실행**: 실제 사용자의 2차 인증 재로그인 수행 및 실시간 네트워크 판정은 미실행.

5. **[8단계] 구역 접근 제어(Zone Access Control) 검증**
   - **실행**: `node --test test/resource-id.test.mjs test/api-owner-scope.test.mjs` 및 판정기 규칙 점검
   - **정상 결과 (허용)**: 허용된 단건 자원 API 경로(`GET/PUT/DELETE /api/notes/:id`, `POST /api/restore`) 허용.
   - **거부되어야 할 결과 (거부)**:
     - 시험 계정 B의 계정 A 메모 접근 시도 거부 (`deny route_not_allowed [zone_access_control]`).
     - 강사 공지 구역에 대한 쓰기(POST/PUT/DELETE) 시도 거부 (`deny route_not_allowed [zone_access_control]`).
     - 메모 전체 목록 일괄 조회 시도 거부 (`deny route_not_allowed [zone_access_control]`).
     - 강사 공지 타입 자원 ID(`instructor-announcement:...`)를 메모 파서에 전달 시 파싱 거부(null).
   - **미실행**: 실제 강사 공지 시스템 연동 및 실제 다중 학생 네트워크 트래픽 차단 실측은 미실행.

6. **[9단계] 도플갱어 폭주 조회 탐지 및 권한 회수 제안 검증**
   - **실행**: `npm run detect:test && node --test test/detect-input.test.mjs`
   - **정상 결과 (허용)**: 10분 구간 내 120건 이하 정상 조회 및 분산 조회 -> `{ action: 'observe' }`로 정상 기기 유지.
   - **거부/제안되어야 할 결과 (탐지 제안)**: 10분 구간 내 동일 가명 사용자 121건 이상 폭주 조회 시 -> `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }` 제안 생성.
   - **미실행**: 실제 기기 권한 취소 API 호출 및 심판 측 회수 완료 여부는 미실행.

7. **[10단계] 백업 사본 단건 복원 및 무결성 대조 검증**
   - **실행**: `node --test test/restore.test.mjs`
   - **정상 결과 (허용)**: 시험 계정 B의 사본과 ID·소유자·내용 해시(SHA-256)가 모두 일치할 때 복원 검증 통과(단 1건 복원).
   - **거부되어야 할 결과 (거부)**: 내용 변조(해시 불일치), 타인 계정(소유자 불일치), 비메모 자원 ID 전달 시 복원 거부.
   - **미실행**: 실제 운영 배포 서버 상에서의 원격 DB 롤백 및 실서버 복원 호출은 미실행.

### 11단계: 나만의 접속 앱을 완성합니다

`aleph.config.json`의 현재 단계는 11이며, 허용 경로에 `/api/device`가 등록되어 있습니다.

* **만들기 1 (설치형 웹앱 및 오프라인 상태 안내)**:
  - `public/manifest.json`: 웹 표준 메타데이터(이름 `BYTE BACK 자료실`, `display: standalone`, 아이콘 등)를 구성하고 `public/index.html`에 연동했습니다.
  - `public/icon.svg`: 설치형 웹앱 표준 아이콘을 추가했습니다.
  - 실시간 오프라인 안내: 네트워크 단절 시 오프라인 경고 배너를 실시간으로 노출합니다.
* **만들기 2 (서버 판정기 계약 기반 기기 승인 화면 및 흐름)**:
  - **승인 전 자료 보호**: 로그인 직후 기기 승인 확인 전에는 보호 자료실(`vault-section`)과 메모 목록을 화면에 일절 표시하지 않습니다.
  - **서버 단일 관문 확인 (`/api/device`)**: 클라이언트 버튼 클릭만으로 권한을 주지 않고, 서버가 JWT 토큰과 판정기 계약(`decider.mjs`의 `deviceRegistered`)을 검증하여 허용(`approved`)된 응답을 보낸 뒤에만 자료실을 엽니다.
  - **기기 키 브라우저 보관 금지**: 기기 비밀키나 세션 키를 LocalStorage나 브라우저 저장소에 일절 보관하지 않습니다.
  - **미등록 기기 거부 검증**: 미등록 기기 요청에 대해 판정기가 `deny (device_not_registered)`로 거부하고 화면을 열지 않습니다.

### 11단계 저장점 확인 완료
* **저장소 클론 및 패키지 설치 무결성**: `npm install` 클린 통과 확인.
* **판정기 계약 무결성**: `src/decider.mjs`가 `docs/DECIDER_REQUEST.md` 18개 이름만 읽고, 모든 가상 요청에 5개 필수 필드를 갖춘 응답을 반환하며, 모든 ruleId가 `RULE_IDS` 목록에 존재함을 확인.
* **설정 단계**: `aleph.config.json`의 `step`이 11로 정상 갱신됨.

### 12단계: 탈환 작전실 운용 안내서 (학생 판정기·탐지 규칙·접속 앱·자료실)
검사 기준 커밋: `80e792d`

#### 1. 출처 및 책임 구분 (학생 몫 vs 제공 엔진)
* **제공 엔진 (ALEPH SDP 엔진 사용)**:
  - **출처 명시**: 본 시스템은 제공된 **ALEPH SDP(Software-Defined Perimeter) 엔진**을 기반으로 동작합니다.
  - **제공 엔진 관할**:
    - 판정기 요청·응답 스키마 계약 규격 (`aleph.decision.v1` / `docs/DECIDER_REQUEST.md`)
    - XDR 경보 및 이상 사건 전달 규격 (`aleph.detect.event.v1` / `docs/DETECT_EVENTS.md`)
    - 배포 신원 검증 프레임워크 (`scripts/deployment-identity.mjs`) 및 심판 접수(`judgeIssuer`) 인터페이스
    - 총공세 41종 종합 심판 판정 집행 엔진
* **학생 몫 (자체 구현 및 검증 영역)**:
  - **학생 판정기 (`src/decider.mjs`)**: 등록 기기 인가(`device_registered`), 추가 인증 요구(`step_up_required`), 이상 대량 읽기(`unusual_bulk_read_step_up`), 구역 격리(`zone_access_control`) 4대 규칙 자체 구현.
  - **탐지 규칙 (`src/detect.mjs`)**: 10분 슬라이딩 윈도우 기반 동일 주체 120건 초과 폭주 조회 탐지(`burst_read`) 및 권한 회수 제안(`propose_revocation`) 알고리즘 자체 구현.
  - **접속 앱 (`public/index.html`, `public/manifest.json`, `api/device.js`)**: 설치형 웹앱(PWA) 표준 구성, 브라우저 저장소 기기 키·토큰 보관 금지(인메모리 격리), 서버 판정기 통과 시에만 자료실을 여는 사전 보호 단일 관문 구현.
  - **자료실 (`api/notes.js`, `api/restore.js`, `src/restore-memo.mjs`, `src/policy-restore.mjs`)**: Supabase 직접 노출 차단, 안전 정책 사본 버전 diff 검증, 비공개 가상 메모 단건 무결성(SHA-256) 대조 복구 구현.

#### 2. 비밀값 취급 및 환경변수 원칙
* **비밀값 포장 금지**:
  - 비밀번호, 서버 비밀키(`SUPABASE_SECRET_KEY`), API 토큰, 기기 개인키를 코드, Git, README, 브라우저 저장소, 제출 묶음에 절대 포함하지 않습니다.
  - 필요한 접속 정보는 Vercel 설정 화면의 **Environment Variables** 또는 로컬 개발 시 학생이 공식 설정 화면의 입력란에 직접 넣습니다.
* **필요 환경변수**:
  - `SUPABASE_URL`: Supabase 프로젝트 HTTPS 주소 (공식 포털에서 확인 후 직접 입력)
  - `SUPABASE_SECRET_KEY`: Supabase `service_role` 서버 전용 키 (공식 포털에서 확인 후 직접 입력)

#### 3. 설치·실행·중지·복구 재현 순서 (Reproducible Steps)

##### (1) 설치 안내 (Install)
1. 저장소를 클론하고 프로젝트 디렉터리로 이동합니다:
   ```sh
   git clone https://github.com/Andy255319/choi-bujang-secret-vault.git
   cd choi-bujang-secret-vault
   ```
2. Node.js 22 이상 환경에서 패키지를 설치합니다:
   ```sh
   npm install
   ```
   - **정상 결과**: 오류나 누락 없이 의존성 패키지가 정상 설치됩니다.

##### (2) 실행 안내 (Run)
1. 정적 에셋 및 배포 메타데이터를 로컬 빌드합니다:
   ```sh
   node scripts/build-public.mjs --local
   ```
   - **정상 결과**: `public/` 정적 파일 빌드 및 보호 모드 전환 확인 출력.
2. 로컬 개발 서버 또는 배포 환경을 실행합니다:
   - 로컬 실행: `npx serve public` 또는 `vercel dev`
   - 배포 환경: Vercel에 커밋 푸시하여 자동 배포 (`https://choi-bujang-secret-vault-kappa.vercel.app`)
3. 웹 브라우저로 접속하여 PWA 설치 배너, 오프라인 상태 감지 및 탈환 작전실 화면 진입을 확인합니다.

##### (3) 검증 및 점검 안내 (Audit & Test)
1. 학생 판정기 가상 요청 연습:
   ```sh
   npm run decider:test
   ```
   - **정상 결과**: 등록 기기 요청 `allow (approved)`, 미등록 기기 `deny (device_not_registered)`, 이상 대량 읽기 `step_up (step_up_required)`.
2. 탐지 규칙 슬라이딩 윈도우 검증:
   ```sh
   npm run detect:test
   ```
   - **정상 결과**: 10분 구간 120건 이하 정상 유지, 121건 이상 폭주 시 `propose_revocation (burst_read)`.
3. 사본 복구 및 무결성 대조 검증:
   ```sh
   node --test test/restore.test.mjs
   ```
   - **정상 결과**: 12건의 무결성 대조 및 사본 부재/변조 시 차단 테스트 100% 통과.
4. 웹 화면 탈환 작전실 실측 점검:
   - 화면 탈환 작전실의 **[1~11단계 실측 점검 절차 실행]** 버튼을 클릭하여 정상 11건 허용 실측 및 금지 11건 거부 실측을 대조 확인합니다.
   - **심판 41종 종합 시험**은 임의 통과 처리하지 않고 `[미실행 (임의 통과 금지)]`로 분리 보존됩니다.
5. 보너스 XDR 알려진 취약점(known-cve) 경보 판정:
   ```sh
   npm run xdr:run -- known-cve
   ```
   - **정상 결과**: 명확한 공격 8건 차단(`block`), 애매한 시도 8건 모니터링 알림(`alert`), 정상 활동 8건 기록(`record`) 총 24건 분류 및 `xdr/known-cve/result.json` 생성.
6. 보너스 XDR 몰래 심어진 프로그램(persistence) 경보 판정:
   ```sh
   npm run xdr:run -- persistence
   ```
   - **정상 결과**: 명확한 공격 8건 차단(`block`), 애매한 시도 8건 모니터링 알림(`alert`), 정상 활동 8건 기록(`record`) 총 24건 분류 및 `xdr/persistence/result.json` 생성.
7. 보너스 XDR 권한 가로채기(privilege) 경보 판정:
   ```sh
   npm run xdr:run -- privilege
   ```
   - **정상 결과**: 명확한 공격 9건 차단(`block`), 애매한 시도 8건 모니터링 알림(`alert`), 정상 활동 9건 기록(`record`) 총 26건 분류 및 `xdr/privilege/result.json` 생성.




##### (4) 중지 안내 (Stop)
1. 로컬 프로세스 종료: 터미널에서 `Ctrl + C`를 입력하여 실행 중인 로컬 웹 서버 프로세스를 안전하게 종료합니다.
2. 기기 승인 상태 회수: 웹 화면에서 **[로그아웃]** 또는 **[미등록 기기 거부 시험]**을 클릭하여 승인 상태를 즉시 미확인/거부로 되돌리고 자료실 화면을 닫습니다.
3. 세션 파기: 브라우저 탭을 닫으면 인메모리 저장소 특성상 모든 기기 키 및 세션 정보가 메모리에서 즉시 소멸합니다.

##### (5) 복구 안내 (Restore)
1. 안전 정책 버전 및 사본 사전 차이 확인 (DryRun):
   ```sh
   # 브라우저 또는 API를 통한 사전 확인 (실제 운영 정책 보존)
   GET /api/restore
   ```
   - **정상 결과**: 정책 사본(`safe_policy_v1`) 및 메모 사본(`backup_v1`)의 변경 대상(`changes`) 사전 확인.
2. 비공개 가상 메모 단건 안전 복원:
   - 사본 원본(`data/backup-notes.json`)과 복원 요청의 ID, 소유자, 내용 해시(SHA-256)가 100% 일치할 때만 복원을 허용합니다.
   - 변조된 내용 해시가 전달되거나 사본이 없으면 `400 content_hash_mismatch / backup_not_found`로 즉시 중단하여 운영 데이터 오염을 차단합니다.
   - 복원 완료 후 다른 계정(A)의 메모나 감사 기록은 손상 없이 보존됩니다.

이 저장소에는 단계별 제작 기록과 코드가 포함되어 있습니다. README 기록은 프로젝트의 실제 실행 결과·배포·심판 판정 자체를 증명하지 않습니다.
