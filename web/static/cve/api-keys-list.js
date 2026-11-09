// The "Your API keys" list on the API keys page: newest first, with when each was made and last used, whether it can write, and only the
// first 4 and last 2 characters of the token. Revoking asks first. The page (api-keys-page.js) loads the data; this draws it.
import { ask, badge, button, el, shortDate, table } from '/staticfiles/cve/ui.js';

// What may be shown of a token, whatever the server sent: its first 4 characters and last 2, never more. The last 2 are not known for a
// key made before they were kept (only a hash of the token exists), and then only the first 4 are shown.
export function keyHint(t) {
  const first = String(t.prefix || '').slice(0, 4);
  const last = String(t.suffix || '').slice(-2);
  return `${first}...${last}`;
}

const when = (t) => Date.parse(t.created) || 0;

// Newest first by creation time; the id breaks a tie (made in the same second), so the order never jumps. Revoked keys are not listed.
export function sortTokens(items) {
  return items.filter((t) => !t.revoked).sort((a, b) => when(b) - when(a) || (b.id || 0) - (a.id || 0));
}

export function accessWords(t) {
  if (t.scope === 'inventory') return `host reporter for ${t.project}`;
  return t.read_only ? 'read only' : 'full access';
}

export function revokeQuestion(t) {
  return `Revoke "${t.name}" (${keyHint(t)}, made ${shortDate(t.created)})? Anything using this key stops working at once. This cannot be undone.`;
}

// onRevoke(token) does the DELETE and reloads; it runs only after the person confirmed.
export function renderTokenList(root, items, onRevoke) {
  const live = sortTokens(items);
  root.textContent = '';
  if (!live.length) return 0;
  const cols = [
    { label: 'Name', cls: 'clip', render: (t) => el('span', 'cve-id', t.name) },
    { label: 'Key', render: (t) => el('code', 'tok-hint', keyHint(t)) },
    { label: 'Access', render: (t) => badge(accessWords(t)) },
    { label: 'Created', render: (t) => shortDate(t.created) },
    { label: 'Last used', render: (t) => (t.last_used ? shortDate(t.last_used) : 'never used') },
    { label: '', render: (t) => button('Revoke', async () => { if (await ask(revokeQuestion(t), { title: 'Revoke this key?', ok: 'Revoke' })) await onRevoke(t); }, 'btn ghost') },
  ];
  root.append(table(cols, live));
  return live.length;
}
