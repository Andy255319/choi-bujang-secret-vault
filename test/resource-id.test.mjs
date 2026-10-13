import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createResourceId, parseMemoResourceId, parseResourceId } from '../src/resource-id.mjs';

test('메모와 강사 공지는 타입이 분리된 자원 ID를 갖는다', () => {
  const memoId = createResourceId('memo', 'existing-note-17');
  const announcementId = createResourceId('instructor-announcement', 'notice-17');

  assert.equal(memoId, 'memo:existing-note-17');
  assert.equal(announcementId, 'instructor-announcement:notice-17');
  assert.notEqual(memoId, announcementId);
  assert.deepEqual(parseResourceId(memoId), { type: 'memo', id: 'existing-note-17' });
  assert.deepEqual(parseResourceId(announcementId), { type: 'instructor-announcement', id: 'notice-17' });
});

test('기존 메모 ID는 보존되고 공지 자원 ID는 메모 요청으로 잘못 해석되지 않는다', () => {
  assert.deepEqual(parseMemoResourceId('existing-note-17'), { type: 'memo', id: 'existing-note-17' });
  assert.deepEqual(parseMemoResourceId('memo:existing-note-17'), { type: 'memo', id: 'existing-note-17' });
  assert.equal(parseMemoResourceId('instructor-announcement:notice-17'), null);
  assert.equal(parseResourceId('unknown:notice-17'), null);
});

test('특수문자 포함 원본 ID는 타입을 유지하며 왕복한다', () => {
  const resourceId = createResourceId('memo', 'folder/old id');
  assert.equal(resourceId, 'memo:folder%2Fold%20id');
  assert.deepEqual(parseResourceId(resourceId), { type: 'memo', id: 'folder/old id' });
});
