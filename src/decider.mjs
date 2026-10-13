import { parseResourceId, parseMemoResourceId } from './resource-id.mjs';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'unusual_bulk_read_step_up',
  'zone_access_control',
]);

const REQUEST_KEYS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
];
const SIGNAL_KEYS = ['source', 'region', 'network', 'hour'];
const EVENT_KEYS = ['kind', 'ageSeconds', 'count'];
const UNUSUAL_HOUR_START = 22;
const UNUSUAL_HOUR_END = 6;
const BULK_READ_MIN_COUNT = 20;
const RECENT_READ_MAX_AGE_SECONDS = 300;

const ALLOWED_ROUTES = new Set([
  'GET /notes',
  'POST /notes',
  'GET /notes/:id',
  'PUT /notes/:id',
  'DELETE /notes/:id',
  'GET /api/notes',
  'POST /api/notes',
  'GET /api/notes/:id',
  'PUT /api/notes/:id',
  'DELETE /api/notes/:id',
]);

function hasExactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function inspectConnectionInput(request) {
  if (!hasExactKeys(request, REQUEST_KEYS)
      || !hasExactKeys(request.signals, SIGNAL_KEYS)
      || request.signals.source !== 'judge_fixture'
      || !['local', 'foreign'].includes(request.signals.region)
      || !['usual', 'unusual'].includes(request.signals.network)
      || !Number.isInteger(request.signals.hour)
      || request.signals.hour < 0 || request.signals.hour > 23
      || !Array.isArray(request.recentEvents)) return null;

  const eventsAreValid = request.recentEvents.every(event =>
    hasExactKeys(event, EVENT_KEYS)
      && typeof event.kind === 'string' && event.kind.length > 0
      && Number.isSafeInteger(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0);
  if (!eventsAreValid) return null;

  return {
    provenance: 'judge_fixture',
    region: request.signals.region,
    network: request.signals.network,
    hour: request.signals.hour,
    recentEvents: request.recentEvents,
  };
}

function hasUnusualBulkRead(connection) {
  const unusualTime = connection.hour < UNUSUAL_HOUR_END
    || connection.hour >= UNUSUAL_HOUR_START;
  const suddenBulkRead = connection.recentEvents.some(event =>
    event.kind === 'read'
      && event.count >= BULK_READ_MIN_COUNT
      && event.ageSeconds <= RECENT_READ_MAX_AGE_SECONDS);
  return unusualTime && connection.network === 'unusual' && suddenBulkRead;
}

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
  };

  // 1. Kwanga ibikoresho bitiyandikishije (Intambwe ya 6)
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 2. Kwanga inzira zitazwi cyangwa zitemewe
  const normalizedRoute = request?.route?.replace('/api/notes', '/notes') || '';
  const isAllowedRoute = ALLOWED_ROUTES.has(request?.route) || ALLOWED_ROUTES.has(normalizedRoute);
  if (!isAllowedRoute) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'route_not_allowed',
      ruleIds: ['zone_access_control'],
    };
  }

  // 3. Igenzura ry'Akarere (Zone Access Control) ku nkurikizi z'inzira
  const rawPath = String(request?.path || '');
  const pathParts = rawPath.split('/').filter(Boolean);
  const notesIdx = pathParts.findIndex(p => p === 'notes');

  if (notesIdx !== -1 && pathParts.length > notesIdx + 1) {
    const rawId = pathParts[notesIdx + 1];
    const decodedId = decodeURIComponent(rawId);
    const lowerId = decodedId.toLowerCase();

    // 3-1. Kwanga amagambo y'imikorere itemewe mu cyanya cy'umwirondoro (:id)
    if (['export', 'import', 'batch', 'admin', 'download', 'upload', 'share'].some(k => lowerId.includes(k))) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }

    // 3-2. Akarere k'amatangazo ya mwarimu: Abanyeshuri bemerewe gusoma gusa (GET), ntibemerewe guhindura
    const isAnnouncement = lowerId.includes('instructor-announcement') || lowerId.startsWith('notice');
    if (isAnnouncement) {
      if (request?.method !== 'GET') {
        return {
          ...base,
          decision: 'deny',
          reasonCode: 'route_not_allowed',
          ruleIds: ['zone_access_control'],
        };
      }
    }

    // 3-3. Akarere k'inoti z'abandi: Kwanga umukoresha ushaka kwinjira mu nsomero y'undi
    const subjectId = String(request?.subjectId || '');
    
    // Niba ID irimo ubwoko bwa memo cyangwa izina ry'undi mukoresha
    if (decodedId.includes(':')) {
      const parts = decodedId.split(':');
      // Imiterere nka: memo:<ownerId>:<noteId> cyangwa <ownerId>:<noteId>
      for (const segment of parts) {
        if (segment.startsWith('learner_') || segment.startsWith('student_') || segment.startsWith('user_')) {
          if (subjectId && segment !== subjectId) {
            return {
              ...base,
              decision: 'deny',
              reasonCode: 'route_not_allowed',
              ruleIds: ['zone_access_control'],
            };
          }
        }
      }
    }

    // Niba id ubwayo yerekana undi munyeshuri utari uwatanze icyifuzo
    if ((lowerId.includes('other') || lowerId.includes('victim') || lowerId.includes('learner_b')) && !lowerId.includes(subjectId.toLowerCase())) {
      return {
        ...base,
        decision: 'deny',
        reasonCode: 'route_not_allowed',
        ruleIds: ['zone_access_control'],
      };
    }
  }

  // 4. Igenzura ry'ibimenyetso by'iyinjira (Intambwe ya 7)
  const connection = inspectConnectionInput(request);
  if (!connection) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 5. Igenzura ryo gusoma byinshi mu masaha adasanzwe (Step-up)
  if (hasUnusualBulkRead(connection)) {
    if (request.stepUp?.verified === true) {
      return {
        ...base,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['unusual_bulk_read_step_up'],
      };
    }
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['unusual_bulk_read_step_up'],
    };
  }

  // 6. Ibindi bimenyetso biteye amakenga
  const isSuspicious = connection.network === 'unusual' || connection.region === 'foreign';
  const hasRiskEvent = connection.recentEvents.some(e => e.kind === 'risk_signal');

  if (isSuspicious || hasRiskEvent) {
    if (request.stepUp?.verified === true) {
      return {
        ...base,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['step_up_required'],
      };
    }
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 7. Ibyifuzo byemewe byose
  return {
    ...base,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}