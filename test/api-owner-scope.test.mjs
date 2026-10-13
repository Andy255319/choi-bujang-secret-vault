import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const listApi = await readFile(new URL('../api/notes.js', import.meta.url), 'utf8');
const itemApi = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
const legacyItemApi = await readFile(new URL('../api/api/notes/[id].js', import.meta.url), 'utf8');

test('목록 API는 저장 owner_id를 검증된 학생과 대조하고 본문 role을 쓰지 않는다', () => {
  assert.match(listApi, /user\.kind !== 'student'/u);
  assert.match(listApi, /select=id,title,content,owner_id&owner_id=eq\.\$\{encodeURIComponent\(ownerId\)\}/u);
  assert.match(listApi, /data\.filter\(n => n\?\.owner_id === ownerId\)/u);
  assert.match(listApi, /owner_id: ownerId/u);
  assert.match(listApi, /verified_student_required/u);
  assert.doesNotMatch(listApi, /req\.body\s*\??\.\s*role|\brole\s*:\s*req\.body/iu);
});

test('단건 조회·수정·삭제는 저장된 소유자가 일치하는 경우만 처리한다', () => {
  const ownerScopedQueries = itemApi.match(/owner_id=eq\.\$\{encodeURIComponent\(ownerId\)\}/gu) ?? [];
  assert.equal(ownerScopedQueries.length, 3, 'GET, PUT, DELETE 모두 owner_id 조건이 있어야 합니다');
  assert.match(itemApi, /not_found_or_not_owner/u);
  assert.match(itemApi, /body: JSON\.stringify\(\{ title, content: body, owner_id: ownerId \}\)/u);
  assert.doesNotMatch(itemApi, /req\.body\s*\??\.\s*role|\brole\s*:\s*req\.body/iu);
});

test('기존 중첩 API 경로도 권한 검사를 우회하지 않는다', () => {
  assert.match(legacyItemApi, /export \{ default \} from '\.\.\/\.\.\/notes\/\[id\]\.js'/u);
  assert.doesNotMatch(legacyItemApi, /fetch\(/u);
});
