// cvengine.live: serves the static site (public/) and saves early-access requests in D1.
// Static asset requests are free on every Cloudflare plan; only /api/* runs this script.

const ADDRESS_BANDS = new Set(['lt500', '500-3000', 'gt3000', 'unknown']);
const EMAIL = /^[^\s@<>"']{1,64}@[^\s@<>"']{1,190}\.[A-Za-z]{2,24}$/;
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;

// Accept "https://www.example.com/path" as well as "example.com"; keep only the host name.
function cleanDomain(value) {
  let v = String(value || '').trim().toLowerCase();
  if (!v) return '';
  v = v.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0].replace(/\.$/, '');
  return DOMAIN.test(v) ? v : null;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

async function earlyAccess(request, env) {
  if (request.method !== 'POST') return json({ error: 'Use POST.' }, 405);
  // Only the site's own pages may post here.
  const origin = request.headers.get('origin');
  if (origin && new URL(origin).host !== new URL(request.url).host) return json({ error: 'Not allowed.' }, 403);
  if (!(request.headers.get('content-type') || '').includes('application/json')) return json({ error: 'Send JSON.' }, 415);
  const raw = await request.text();
  if (raw.length > 4096) return json({ error: 'That request is too large.' }, 413);

  let data;
  try { data = JSON.parse(raw); } catch { return json({ error: 'That request could not be read.' }, 400); }
  if (data.website) return json({ ok: true }); // the hidden field: a bot filled it in, so drop it quietly

  const email = String(data.email || '').trim().toLowerCase();
  const company = String(data.company || '').trim().slice(0, 200);
  const addresses = ADDRESS_BANDS.has(data.addresses) ? data.addresses : 'unknown';
  if (!EMAIL.test(email)) return json({ error: 'Enter a work email address so we can reach you.' }, 400);
  if (!company) return json({ error: 'Enter your company name.' }, 400);
  const domain = cleanDomain(data.domain);
  if (domain === null) return json({ error: 'Enter a domain like yourcompany.com, or leave it empty.' }, 400);

  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO early_access (email, company, domain, addresses, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
     ON CONFLICT(email) DO UPDATE SET company = excluded.company, domain = excluded.domain, addresses = excluded.addresses, updated_at = excluded.updated_at`
  ).bind(email, company, domain, addresses, now).run();
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/early-access') {
      try { return await earlyAccess(request, env); }
      catch (err) { console.error('early-access failed', err); return json({ error: 'We could not save your request. Try again in a minute.' }, 500); }
    }
    if (url.pathname.startsWith('/api/')) return json({ error: 'Not found.' }, 404);
    return env.ASSETS.fetch(request);
  },
};
