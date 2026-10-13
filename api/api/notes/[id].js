// Preserve the legacy nested URL while routing it through the same authenticated,
// owner-scoped handler as /api/notes/:id. This prevents an alternate-path bypass.
export { default } from '../../notes/[id].js';
