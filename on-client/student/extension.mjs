// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
const DEVICE_STATUS_LABELS = {
  compliant: '보안 기준 충족',
  noncompliant: '보안 기준 미충족',
  unknown: '확인 불가',
};

const SESSION_STATUS_LABELS = {
  active: '활성',
  expired: '만료',
  revoked: '철회됨',
  unknown: '확인 불가',
};

const MODE_LABELS = {
  demo: '예제 자료',
  disconnected: '연결 없음',
  unknown: '확인 불가',
};

function formatDeviceStatus(status) {
  const label = DEVICE_STATUS_LABELS[status] || '확인 불가';
  return status ? `${label}(${status})` : label;
}

function formatSessionStatus(status) {
  const label = SESSION_STATUS_LABELS[status] || '확인 불가';
  return status ? `${label}(${status})` : label;
}

const DECISION_LABELS = {
  allow: '접근 허용(allow)',
  deny: '접근 거부(deny)',
  challenge: '추가 인증 또는 확인 필요(challenge)',
  unknown: '판정 확인 불가(unknown)',
};

function formatDecision(decision) {
  return DECISION_LABELS[decision] || '판정 확인 불가(unknown)';
}

function formatCheckedAt(value) {
  if (typeof value !== 'string' || !value) return '시각 정보 없음';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('ko-KR');
}

export function createStudentView() {
  return {
    renderIdentity(input) {
      const root = document.createElement('div');
      root.className = 'student-identity-view';

      if (!input) {
        const empty = document.createElement('p');
        empty.className = 'state state-empty';
        empty.textContent = '확인 불가';
        root.appendChild(empty);
        return root;
      }

      const me = input.me || (input.status ? input : null);
      const devices = input.devices;
      const sessions = input.sessions;

      // 1. 모드 안내 (demo, disconnected, unknown) - me, devices, sessions 각각 확인하여 표시
      const checkedModes = new Set();
      for (const res of [me, devices, sessions]) {
        const m = res?.mode;
        if (m && MODE_LABELS[m] && !checkedModes.has(m)) {
          checkedModes.add(m);
          const modeBadge = document.createElement('span');
          modeBadge.className = 'tag tag-demo';
          modeBadge.textContent = MODE_LABELS[m];
          root.appendChild(modeBadge);
        }
      }

      // 2. me (사용자 계정, 현재 기기, 현재 세션) 상태 처리
      if (!me || me.status === 'loading') {
        const loading = document.createElement('p');
        loading.className = 'state state-loading';
        loading.textContent = '불러오는 중';
        root.appendChild(loading);
      } else if (me.status === 'error') {
        const error = document.createElement('p');
        error.className = 'state state-error';
        const msg = me.error?.message || '서버에 연결하지 못했습니다.';
        error.textContent = '연결 실패: ' + msg;
        root.appendChild(error);
      } else if (me.status === 'ok') {
        const dl = document.createElement('dl');
        dl.className = 'identity';

        // 사용자
        const userDt = document.createElement('dt');
        userDt.textContent = '사용자';
        const userDd = document.createElement('dd');
        const user = me.data?.user;
        userDd.textContent = (user && (user.label || user.id)) || '확인 불가';
        dl.appendChild(userDt);
        dl.appendChild(userDd);

        // 기기
        const deviceDt = document.createElement('dt');
        deviceDt.textContent = '기기';
        const deviceDd = document.createElement('dd');
        const device = me.data?.device;
        const deviceName = (device && (device.label || device.id)) || '확인 불가';
        const deviceStatus = formatDeviceStatus(device?.status);
        deviceDd.textContent = `${deviceName} · ${deviceStatus}`;
        dl.appendChild(deviceDt);
        dl.appendChild(deviceDd);

        // 세션
        const sessionDt = document.createElement('dt');
        sessionDt.textContent = '세션';
        const sessionDd = document.createElement('dd');
        const session = me.data?.session;
        const sessionId = (session && session.id) || '확인 불가';
        const sessionStatus = formatSessionStatus(session?.status);
        sessionDd.textContent = `${sessionId} · ${sessionStatus}`;
        dl.appendChild(sessionDt);
        dl.appendChild(sessionDd);

        root.appendChild(dl);
      }

      // 3. devices 및 sessions 상태 처리 (loading / ok / error)
      if (devices && devices !== me) {
        if (devices.status === 'error') {
          const devErr = document.createElement('p');
          devErr.className = 'state state-error';
          devErr.textContent = '기기 목록 연결 실패: ' + (devices.error?.message || '조회 실패');
          root.appendChild(devErr);
        } else if (devices.status === 'loading' && me?.status === 'ok') {
          const devLoading = document.createElement('p');
          devLoading.className = 'muted';
          devLoading.textContent = '기기 목록: 불러오는 중';
          root.appendChild(devLoading);
        }
      }

      if (sessions && sessions !== me) {
        if (sessions.status === 'error') {
          const sessErr = document.createElement('p');
          sessErr.className = 'state state-error';
          sessErr.textContent = '세션 목록 연결 실패: ' + (sessions.error?.message || '조회 실패');
          root.appendChild(sessErr);
        } else if (sessions.status === 'loading' && me?.status === 'ok') {
          const sessLoading = document.createElement('p');
          sessLoading.className = 'muted';
          sessLoading.textContent = '세션 목록: 불러오는 중';
          root.appendChild(sessLoading);
        }
      }

      return root;
    },
    renderDecision(input) {
      const root = document.createElement('div');
      root.className = 'student-decision-view';

      // 1. 요청 전 (idle)
      if (!input || input.status === 'idle') {
        const p = document.createElement('p');
        p.className = 'state state-empty';
        p.textContent = '앱을 골라 접속을 요청하세요.';
        root.appendChild(p);
        return root;
      }

      // 2. 요청 중 (loading)
      if (input.status === 'loading') {
        const p = document.createElement('p');
        p.className = 'state state-loading';
        const appText = input.appId ? `[${input.appId}] ` : '';
        p.textContent = `${appText}판정 확인 중…`;
        root.appendChild(p);
        return root;
      }

      // 3. 요청 실패 (error) - 접근 거부(차단) 판정과 명확히 구분
      if (input.status === 'error') {
        const p = document.createElement('p');
        p.className = 'state state-error';
        const msg = input.error?.message || '판정 요청에 실패했습니다.';
        p.textContent = `요청 실패: ${msg}`;
        root.appendChild(p);

        const note = document.createElement('p');
        note.className = 'muted';
        note.textContent = '요청 실패는 접근 거부(차단) 판정이 아닙니다. 접근이 허용되지 않았습니다.';
        root.appendChild(note);
        return root;
      }

      // 4. 판정 수신 (ok)
      if (input.status === 'ok') {
        const data = input.data || {};
        const appId = data.appId || input.appId || '알 수 없음';
        const rawDecision = data.decision;
        const decisionText = formatDecision(rawDecision);
        const reason = data.reason || '사유 정보 없음';
        const checkedAt = formatCheckedAt(data.checkedAt);

        // 모드 배지 (demo, disconnected, unknown)
        if (input.mode && MODE_LABELS[input.mode]) {
          const modeBadge = document.createElement('span');
          modeBadge.className = 'tag tag-demo';
          modeBadge.textContent = MODE_LABELS[input.mode];
          root.appendChild(modeBadge);
        }

        // 판정 결과 배너/문구
        const decisionP = document.createElement('p');
        const decisionClass = ['allow', 'deny', 'challenge'].includes(rawDecision) ? rawDecision : 'unknown';
        decisionP.className = `decision decision-${decisionClass}`;
        decisionP.textContent = `판정 결과: ${decisionText} · 대상 앱: ${appId}`;
        root.appendChild(decisionP);

        // 추가 안내문: challenge 및 unknown
        if (rawDecision === 'challenge') {
          const challengeNote = document.createElement('p');
          challengeNote.className = 'muted';
          challengeNote.textContent = '추가 확인이 필요합니다. 이 앱은 확인 절차를 대신 수행하지 않습니다.';
          root.appendChild(challengeNote);
        } else if (decisionClass === 'unknown') {
          const unknownNote = document.createElement('p');
          unknownNote.className = 'muted';
          unknownNote.textContent = '판정을 확인할 수 없습니다. 접근이 허용되지 않았습니다.';
          root.appendChild(unknownNote);
        }

        // 판정 상세 정보 (dl.kv)
        const dl = document.createElement('dl');
        dl.className = 'kv';

        const dtApp = document.createElement('dt');
        dtApp.textContent = '업무 앱';
        const ddApp = document.createElement('dd');
        ddApp.textContent = appId;
        dl.appendChild(dtApp);
        dl.appendChild(ddApp);

        const dtDecision = document.createElement('dt');
        dtDecision.textContent = '접속 판정';
        const ddDecision = document.createElement('dd');
        ddDecision.textContent = decisionText;
        dl.appendChild(dtDecision);
        dl.appendChild(ddDecision);

        const dtReason = document.createElement('dt');
        dtReason.textContent = '판정 이유';
        const ddReason = document.createElement('dd');
        ddReason.textContent = reason;
        dl.appendChild(dtReason);
        dl.appendChild(ddReason);

        const dtTime = document.createElement('dt');
        dtTime.textContent = '판정 시각';
        const ddTime = document.createElement('dd');
        ddTime.textContent = checkedAt;
        dl.appendChild(dtTime);
        dl.appendChild(ddTime);

        root.appendChild(dl);
        return root;
      }

      return root;
    },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
