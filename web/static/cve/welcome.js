// First-run setup: the way a new install is set up (the installer only prints this page's address).
// Step 1 asks only what a discovery needs (organization, project, ONE seed domain) and starts it in the background; steps 2 to 4 are answered
// while it runs; step 5 shows it building, then opens the dashboard with the findings. Everything is saved on the server step by step, so the
// page resumes where you left it from any browser, and what you typed is kept in this tab until it is saved.
const root = document.getElementById('wizard');
const csrf = root.querySelector('[name=csrfmiddlewaretoken]').value;
const stepBox = document.getElementById('step');
const dots = document.getElementById('dots');
const discBar = document.getElementById('disc');
const discText = document.getElementById('disc-text');
const STEPS = ['seed', 'plan', 'scanners', 'extras', 'build'];
const TITLES = ['Start discovering', 'How you scan', 'What runs', 'Optional extras', 'Building'];
const NAMES = { anthropic: 'Anthropic', openai: 'OpenAI', openrouter: 'OpenRouter' };

const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

async function api(method, path, body) {
  const res = await fetch(path, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (!res.ok) throw new Error(data.error || `Something went wrong (${res.status})`);
  return data;
}
const welcome = (m, p, b) => api(m, `/cve/api/welcome/${p}`, b);

// What was typed survives a failed save or a reload of this tab (never a password or a key).
const keep = (id, input) => {
  try { const v = sessionStorage.getItem(`wiz.${id}`); if (v != null && !input.value) input.value = v; } catch (_) { /* storage blocked */ }
  input.addEventListener('input', () => { try { sessionStorage.setItem(`wiz.${id}`, input.value); } catch (_) { /* storage blocked */ } });
  return input;
};

function field(label, input, help) {
  const wrap = el('div', 'field');
  const id = `f-${label.replace(/\W/g, '')}`;
  input.id = id;
  wrap.append(el('label', '', label, { for: id }), input);
  if (help) wrap.append(el('p', 'note', help, { style: 'margin:6px 0 0' }));
  return wrap;
}

let state = {};
let index = 0;
let timer = null;
const stop = () => { clearInterval(timer); timer = null; };

function drawDots() {
  dots.textContent = '';
  STEPS.forEach((_, i) => dots.append(el('i', i <= index ? 'on' : '')));
}

function show(i) {
  stop();
  index = i;
  drawDots();
  stepBox.textContent = '';
  const node = el('div', 'step');
  stepBox.append(node);
  node.append(el('p', 'stepname', `Step ${i + 1} of ${STEPS.length}: ${TITLES[i]}`));
  steps[STEPS[i]](node);
  window.scrollTo(0, 0);
}
const next = () => show(Math.min(index + 1, STEPS.length - 1));
const back = () => show(Math.max(index - 1, 0));

function form(node, { title, lead, body, primary, onSubmit, skip, canBack = true }) {
  node.append(el('h1', '', title), el('p', 'lead', lead));
  const f = el('form');
  const msg = el('div', 'msg err', '', { role: 'alert', style: 'display:none;margin:0 0 12px' });
  body.forEach((b) => f.append(b));
  const actions = el('div', 'actions');
  if (canBack && index > 0) { const b = el('button', 'btn ghost', 'Back', { type: 'button' }); b.onclick = back; actions.append(b); }
  actions.append(el('span', 'grow'));
  if (skip) {
    const s = el('button', 'skip', skip.label, { type: 'button' });
    s.onclick = async () => { try { await skip.onClick(); } catch (err) { msg.textContent = err.message; msg.style.display = 'block'; } };
    actions.append(s);
  }
  const go = el('button', 'btn', primary, { type: 'submit' });
  actions.append(go);
  f.append(msg, actions);
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    go.disabled = true; msg.style.display = 'none';
    try { await onSubmit(); } catch (err) { msg.textContent = err.message; msg.style.display = 'block'; }
    go.disabled = false;
  });
  node.append(f);
  const first = f.querySelector('input:not([type=checkbox]):not([type=radio]),select');
  if (first) first.focus();
  return f;
}

// --- the discovery strip: shown from step 2 on, so it is clear the first discovery is already running --------------------------------
async function pollStrip() {
  try {
    const r = await welcome('GET', 'progress');
    if (r.discovery) { discBar.classList.add('on'); discText.textContent = r.discovery.text; }
  } catch (_) { /* the next poll tries again */ }
}

// --- external Sentinels: the real enrollment, inside the wizard ---------------------------------------------------------------------
function sentinelPanel() {
  const panel = el('div', 'panel');
  panel.append(el('h3', '', 'Connect an external Sentinel'),
    el('p', 'note', 'A Sentinel is a small scanner you run on another machine with Docker. This makes a one-time install command for it. It is a secret that works once and expires in 30 minutes: it is shown here only.', { style: 'margin:0 0 10px' }));
  const out = el('div'); const status = el('div', 'note', '', { 'aria-live': 'polite', style: 'margin-top:10px' });
  const msg = el('div', 'msg err', '', { role: 'alert', style: 'display:none' });
  const make = el('button', 'btn sm', 'Create the install command', { type: 'button' });
  make.onclick = async () => {
    make.disabled = true; msg.style.display = 'none';
    try {
      const r = await welcome('POST', 'provision', { profile: 'light' });
      out.textContent = '';
      const area = el('textarea', 'cmd', null, { readonly: '', 'aria-label': 'Sentinel install command', spellcheck: 'false' }); area.value = r.command;
      const copy = el('button', 'btn ghost sm', 'Copy', { type: 'button', style: 'margin-top:8px' });
      copy.onclick = async () => { try { await navigator.clipboard.writeText(r.command); copy.textContent = 'Copied'; } catch (_) { area.select(); } };
      out.append(el('p', 'note', `Run this on the machine (needs Docker and outbound HTTPS to this server). Expires ${new Date(r.expires_at).toLocaleTimeString()}.`, { style: 'margin:0 0 6px' }), area, copy);
      refresh();
    } catch (e) { msg.textContent = e.message; msg.style.display = 'block'; }
    make.disabled = false;
  };
  panel.append(make, out, status, msg);
  const refresh = async () => {
    try {
      const s = await welcome('GET', 'state'); state = s;
      const lines = s.enrollments.map((e) => e.agent
        ? `Sentinel "${e.agent.name}": ${e.agent.live ? 'connected and live' : e.agent.status === 'active' ? 'connected, waiting for its first heartbeat' : e.agent.status}`
        : e.expired ? 'An install command expired before it was used.' : 'Waiting for the command to run on your machine...');
      status.textContent = lines.length ? lines.join(' \u00b7 ') : '';
    } catch (_) { /* the next poll tries again */ }
  };
  refresh();
  const t = setInterval(() => { if (!document.body.contains(panel)) clearInterval(t); else refresh(); }, 3000);
  return panel;
}

const steps = {
  seed(node) {
    const org = keep('org', el('input', '', null, { value: state.seed.org, placeholder: 'Acme Security', autocomplete: 'organization', required: '' }));
    const project = keep('project', el('input', '', null, { value: state.seed.project, placeholder: 'Production', required: '' }));
    const domain = keep('domain', el('input', '', null, { value: state.seed.domain, placeholder: 'example.com', required: '', spellcheck: 'false', autocapitalize: 'none', inputmode: 'url' }));
    const auth = el('input', '', null, { type: 'checkbox', id: 'authorized' });
    if (state.seed.domain) auth.checked = true;
    const authWrap = el('label', 'check', null, { for: 'authorized' });
    authWrap.append(auth, document.createTextNode('I am authorized to test this domain.'));
    const hint = el('div', 'live-hint');
    hint.append(el('span', 'live', 'live'), document.createTextNode('Discovery starts the moment you continue, with public data sources only, and keeps running while you answer the next questions.'));
    form(node, {
      title: 'Let us start finding your hosts',
      lead: 'Name your organization and first project, and give one domain you own. We begin discovering it right away.',
      body: [field('Organization', org, 'The top level: your projects and teammates live inside it.'),
        field('Project', project, 'Holds your targets, scans and findings. Examples: Production, Client A, Lab.'),
        field('Seed domain', domain, 'One domain. Subdomains are found for you; more targets can be added later.'), authWrap, hint],
      primary: state.seed.domain ? 'Save and continue' : 'Start discovering', canBack: false,
      onSubmit: async () => {
        if (!auth.checked) throw new Error('Please confirm you are authorized to test this domain.');
        state = await welcome('POST', 'seed', { org: org.value, project: project.value, domain: domain.value, authorized: true });
        next();
      },
    });
  },

  plan(node) {
    const builtin = state.builtin;
    const options = [
      ['internal', 'The built-in scanner only', 'Scans run on this server, by the scanner that came with it. The simplest start; nothing else to install.'],
      ['both', 'The built-in scanner plus external Sentinels', 'You also connect scanners on other machines or networks. They take the work first; the built-in scanner stays as the last resort for anything none of them can take.'],
      ['external', 'External Sentinels only', 'Scans run only on Sentinels you install on other machines. The built-in scanner is turned off for scans once setup is finished (it still completes your first discovery).'],
    ];
    let chosen = state.plan;
    const box = el('div', 'choice', null, { role: 'radiogroup', 'aria-label': 'How will you scan?' });
    const external = el('div');
    const draw = () => { external.textContent = ''; if (chosen !== 'internal') external.append(sentinelPanel()); };
    options.forEach(([id, title, about]) => {
      const blocked = id !== 'external' && !builtin.enabled;
      const label = el('label', blocked ? 'off' : '');
      const radio = el('input', '', null, { type: 'radio', name: 'plan', value: id });
      radio.checked = chosen === id; radio.disabled = blocked;
      radio.addEventListener('change', () => { chosen = id; draw(); });
      const c = el('div'); c.append(el('b', '', title), el('span', '', blocked ? `${about} Not available: the built-in scanner is switched off on this install.` : about));
      label.append(radio, c); box.append(label);
    });
    const status = el('p', 'note', builtin.text, { style: 'margin:-6px 0 16px' });
    draw();
    form(node, {
      title: 'How will you scan?', lead: 'Pick where your scans run. You can change this later in Sentinels.',
      body: [box, status, external], primary: 'Continue',
      onSubmit: async () => { state = await welcome('POST', 'plan', { plan: chosen }); next(); },
      skip: { label: 'Skip: keep the built-in scanner', onClick: async () => { state = await welcome('POST', 'skip', { step: 'plan' }); next(); } },
    });
    pollStrip(); timer = setInterval(pollStrip, 5000);
  },

  scanners(node) {
    const boxes = {};
    const list = el('div');
    const mem = state.memory_gb;
    list.append(el('p', 'note', mem
      ? `Suggested for this machine (${mem} GB of memory): ${state.suggested_off.length ? 'the heavy checks start off.' : 'everything but OpenVAS starts on.'} Change anything you like.`
      : 'Suggested for a small server: the heavy checks start off. Change anything you like.', { style: 'margin:0 0 12px' }));
    state.families.forEach((f) => {
      const card = el('div', 'fam');
      const master = el('input', '', null, { type: 'checkbox', 'aria-label': `${f.title}: all` });
      const head = el('header'); head.append(master, el('b', '', f.title));
      const ul = el('ul');
      const syncMaster = () => {
        const unlocked = f.kinds.filter((k) => !k.locked);
        master.checked = unlocked.every((k) => boxes[k.kind].checked);
        master.indeterminate = !master.checked && unlocked.some((k) => boxes[k.kind].checked);
        master.disabled = !unlocked.length;
      };
      f.kinds.forEach((k) => {
        const li = el('li'); const l = el('label');
        const cb = el('input', '', null, { type: 'checkbox', 'data-kind': k.kind }); cb.checked = k.on; cb.disabled = k.locked;
        boxes[k.kind] = cb; cb.addEventListener('change', syncMaster);
        l.append(cb, document.createTextNode(k.label));
        if (k.heavy) l.append(el('span', 'tag', 'heavy'));
        li.append(l); ul.append(li);
      });
      master.addEventListener('change', () => { f.kinds.forEach((k) => { if (!k.locked) boxes[k.kind].checked = master.checked; }); syncMaster(); });
      syncMaster();
      card.append(head, el('p', '', f.about), ul); list.append(card);
    });
    // OpenVAS is its own group, off unless asked for, with its real cost and where it runs.
    const ov = state.openvas;
    const vas = el('div', 'fam vas');
    const vasOn = el('input', '', null, { type: 'checkbox', 'aria-label': 'Turn OpenVAS on', id: 'vas-on' }); vasOn.checked = ov.enabled;
    const vh = el('header'); vh.append(vasOn, el('b', '', 'OpenVAS (a second scanner, off by default)'));
    const where = el('div', 'choice', null, { style: 'margin:8px 0 0' });
    const allowed = state.plan === 'internal' ? ['internal'] : state.plan === 'external' ? ['external'] : ['internal', 'external', 'both'];
    const WHERE = { internal: 'On the built-in scanner', external: 'On an external Sentinel', both: 'On both' };
    let wsel = allowed.includes(ov.where) ? ov.where : allowed[0];
    allowed.forEach((w) => {
      const l = el('label'); const r = el('input', '', null, { type: 'radio', name: 'vwhere', value: w }); r.checked = wsel === w;
      r.addEventListener('change', () => { wsel = w; });
      const c = el('div'); c.append(el('b', '', WHERE[w]));
      if (w !== 'internal') c.append(el('span', '', 'The Sentinel must run the Full profile, which carries the Greenbone stack.'));
      l.append(r, c); where.append(l);
    });
    const sync = () => { where.style.display = vasOn.checked ? '' : 'none'; };
    vasOn.addEventListener('change', sync); sync();
    vas.append(vh, el('p', '', ov.cost), where); list.append(vas);
    form(node, {
      title: 'What should run?', lead: 'Scanner types are grouped by what they find. Anything you leave off never runs, on the built-in scanner or on external Sentinels.',
      body: [list], primary: 'Continue',
      onSubmit: async () => {
        const kinds = {}; Object.entries(boxes).forEach(([k, cb]) => { if (!cb.disabled) kinds[k] = cb.checked; });
        state = await welcome('POST', 'scanners', { kinds, openvas: { enabled: vasOn.checked, where: wsel } });
        next();
      },
      skip: { label: 'Skip: use the suggested ones', onClick: async () => { state = await welcome('POST', 'skip', { step: 'scanners' }); next(); } },
    });
    pollStrip(); timer = setInterval(pollStrip, 5000);
  },

  extras(node) {
    node.append(el('h1', '', 'Optional extras'), el('p', 'lead', 'Each one is optional and can be done later in Settings. Discovery keeps running meanwhile.'));
    const done = (name) => (state.extras || {})[name];
    const mark = async (name, how) => { state = await welcome('POST', 'extra', { name, how }); render(); };
    const card = (name, title, about, bodyNodes, onSave, saveLabel = 'Save') => {
      const box = el('div', 'extra');
      const h = el('h3'); h.append(document.createTextNode(title), el('span', `st ${done(name) === 'done' ? 'done' : ''}`, done(name) === 'done' ? 'saved' : done(name) === 'skipped' ? 'skipped' : ''));
      const msg = el('div', 'msg err', '', { role: 'alert', style: 'display:none' });
      const actions = el('div', 'actions'); actions.append(el('span', 'grow'));
      const skip = el('button', 'skip', 'Skip', { type: 'button', 'data-extra': name });
      skip.onclick = () => mark(name, 'skipped').catch((e) => { msg.textContent = e.message; msg.style.display = 'block'; });
      const save = el('button', 'btn sm', saveLabel, { type: 'button', 'data-save': name });
      save.onclick = async () => { save.disabled = true; msg.style.display = 'none'; try { await onSave(); } catch (e) { msg.textContent = e.message; msg.style.display = 'block'; } save.disabled = false; };
      actions.append(skip, save);
      box.append(h, el('p', 'note', about, { style: 'margin:0 0 10px' }), ...bodyNodes, msg, actions);
      return box;
    };
    const holder = el('div'); node.append(holder);

    function render() {
      holder.textContent = '';
      // AI model
      const key = el('input', '', null, { type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: state.ai.connected ? 'Connected. Paste a new key only to replace it.' : 'sk-ant-...  or  sk-...' });
      const hint = el('p', 'note', 'Anthropic (sk-ant-...), OpenRouter (sk-or-...) or OpenAI (sk-proj-...): we detect which one it is. Ollama, vLLM and LM Studio are set up in Settings. The key is stored in your database and never shown again.', { style: 'margin:6px 0 0' });
      // A bare sk- key is issued by more than one vendor: it is never guessed onto one, the person says whose it is.
      const pick = el('select');
      pick.append(Object.assign(el('option'), { value: '', textContent: 'Choose the provider' }),
        ...Object.entries(NAMES).map(([id, label]) => Object.assign(el('option'), { value: id, textContent: label })));
      const pickField = field('Provider', pick, 'Many vendors issue keys that start with sk- (OpenAI, DeepSeek and others), so choose the one this key belongs to: the key is sent only there.');
      pickField.style.display = 'none';
      const detect = () => api('POST', '/cve/api/setup/detect', { key: key.value }).catch(() => ({}));
      let t;
      key.addEventListener('input', () => {
        clearTimeout(t);
        t = setTimeout(async () => {
          if (!key.value.trim()) { pickField.style.display = 'none'; return; }
          const r = await detect();
          pickField.style.display = r.provider ? 'none' : '';
          if (r.provider) pick.value = '';
          hint.textContent = r.provider ? `That looks like an ${NAMES[r.provider]} key.`
            : r.ambiguous ? 'More than one vendor issues keys like this one. Choose the provider below.' : 'We do not recognize that key. Choose the provider below, or pick one in Settings.';
        }, 250);
      });
      const kf = el('div', 'field'); kf.append(el('label', '', 'API key', { for: 'ai-key' }), key, hint); key.id = 'ai-key';
      holder.append(card('ai', 'Connect an AI model', 'It reads the CVE feed, checks your inventory, and writes and runs checks.', [kf, pickField], async () => {
        if (!key.value.trim()) throw new Error('Paste a key, or choose "Skip".');
        if (!pick.value && !(await detect()).provider) { pickField.style.display = ''; throw new Error('Choose which provider this key belongs to. Nothing was sent anywhere.'); }
        const r = await api('POST', '/cve/api/setup/save', { key: key.value, provider: pick.value || undefined });
        key.value = '';
        if (r.needs_model) hint.textContent = `Connected to ${NAMES[r.provider] || r.provider}. Choose its model in Settings > AI model, then turn it on.`;
        state.ai = { connected: !r.needs_model, provider: r.provider };
        await mark('ai', 'done');
      }, 'Verify and save'));

      // Notifications
      const svc = el('select'); svc.append(Object.assign(el('option'), { value: 'slack', textContent: 'Slack' }), Object.assign(el('option'), { value: 'discord', textContent: 'Discord' }));
      const url = el('input', '', null, { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: state.notify.slack || state.notify.discord ? 'A webhook is already saved. Paste a new one to replace it.' : 'https://hooks.slack.com/services/...' });
      const nb = el('div'); nb.append(field('Where', svc), field('Webhook address', url, 'Stored encrypted and never shown again. Telegram and more are in Settings > Notifications.'));
      holder.append(card('notify', 'Notifications', 'Get told about new findings and finished scans in Slack or Discord.', [nb], async () => {
        if (!url.value.trim()) throw new Error('Paste a webhook address, or choose "Skip".');
        state = await welcome('POST', 'notify', { service: svc.value, url: url.value }); url.value = ''; render();
      }));

      // Time zone
      const tzNow = (() => { try { return localStorage.getItem('cve.tz') === 'utc' ? 'utc' : 'local'; } catch (_) { return 'local'; } })();
      const local = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'your time zone'; } catch (_) { return 'your time zone'; } })();
      const tz = el('select'); tz.append(Object.assign(el('option'), { value: 'local', textContent: `My time zone (${local})` }), Object.assign(el('option'), { value: 'utc', textContent: 'UTC' }));
      tz.value = tzNow;
      holder.append(card('timezone', 'Time zone', 'How times are shown in this browser. You can switch any time from the account menu.', [field('Show times in', tz)], async () => {
        try { localStorage.setItem('cve.tz', tz.value); } catch (_) { /* blocked storage: the choice just does not stick */ }
        await mark('timezone', 'done');
      }));

      // Password
      const cur = el('input', '', null, { type: 'password', autocomplete: 'current-password' });
      const nw = el('input', '', null, { type: 'password', autocomplete: 'new-password' });
      const again = el('input', '', null, { type: 'password', autocomplete: 'new-password' });
      const pb = el('div'); pb.append(field('Current password', cur), field('New password', nw, 'At least 12 characters is a good length.'), field('New password again', again));
      holder.append(card('password', 'Choose your own password', 'If you were given a generated one, replace it now. The built-in scanner keeps working while you do.', [pb], async () => {
        if (!cur.value || !nw.value) throw new Error('Enter your current and a new password, or choose "Skip".');
        if (nw.value !== again.value) throw new Error('The two new passwords differ.');
        state = await welcome('POST', 'password', { current: cur.value, new: nw.value });
        cur.value = nw.value = again.value = ''; render();
      }, 'Change password'));

      const actions = el('div', 'actions');
      const b = el('button', 'btn ghost', 'Back', { type: 'button' }); b.onclick = back;
      actions.append(b, el('span', 'grow'));
      const go = el('button', 'btn', 'Continue', { type: 'button', id: 'extras-continue' });
      go.onclick = async () => { go.disabled = true; try { await welcome('POST', 'skip', { step: 'extras' }); } catch (_) { /* proceed anyway */ } next(); };
      actions.append(go); holder.append(actions);
    }
    render();
    pollStrip(); timer = setInterval(pollStrip, 5000);
  },

  build(node) {
    discBar.classList.remove('on');  // the building screen shows the same live counts itself
    node.append(el('h1', '', 'Building your workspace'),
      el('p', 'lead', 'The first discovery is running. This is what is really happening, so you can see it is not just a spinner.'));
    // The scene is the maintenance page's own two engineers. It is fetched and given to the frame as its document (srcdoc) so that no framing header on the
    // static file (Django's X-Frame-Options, a proxy's) can blank it; ``data-scene`` is set here because a srcdoc page has no query string to read it from.
    const frame = el('iframe', 'scene', null, { title: 'Two engineers at work', loading: 'eager' });
    fetch('/static/cve/maintenance.html', { credentials: 'same-origin' }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(String(r.status)))))
      .then((html) => { frame.srcdoc = html.replace('<html', '<html data-scene="1"'); })
      .catch(() => { frame.remove(); });
    const lines = ['Sentinel ready', 'Discovery running', 'Hosts found'].map((t) => {
      const li = el('li'); const g = el('span', 'g', ''); const c = el('div'); const b = el('span', '', t); const sm = el('small', '', '');
      c.append(b, sm); li.append(g, c); return { li, g, sm, b };
    });
    const list = el('ul', 'steps-list', null, { id: 'build-steps' }); lines.forEach((l) => list.append(l.li));
    const recent = el('p', 'recent', '');
    const wait = el('p', 'note', '', { id: 'build-wait' });
    const meter = el('span', ''); const track = el('div', 'meter', null, { role: 'progressbar', 'aria-label': 'Time given to discovery' }); track.append(meter);
    const actions = el('div', 'actions'); actions.append(el('span', 'grow'));
    const skip = el('button', 'btn ghost', 'Skip: open the dashboard now', { type: 'button', id: 'build-skip' });
    actions.append(skip);
    node.append(frame, list, recent, track, wait, actions);
    let leaving = false;
    const leave = async (follow) => {
      if (leaving) return; leaving = true; stop();
      try { const r = await welcome('POST', 'finish'); follow = follow || r.follow; } catch (_) { /* the dashboard opens regardless */ }
      window.location.href = follow ? `/cve/?follow=${follow}` : '/cve/';
    };
    skip.onclick = () => leave();
    const say = (text) => { try { frame.contentWindow.postMessage({ state: text }, location.origin); } catch (_) { /* not loaded yet */ } };
    frame.addEventListener('load', () => say('Starting up.'));
    const set = (l, mode, sub) => { l.li.className = mode; l.g.textContent = mode === 'ok' ? '\u2713' : mode === 'run' ? '\u2026' : ''; l.sm.textContent = sub || ''; };
    let landing = false;
    const poll = async () => {
      let r;
      try { r = await welcome('GET', 'progress'); } catch (err) { say(err.message); return; }
      const s = r.sentinel, d = r.discovery;
      set(lines[0], s.live ? 'ok' : 'run', s.live ? `${s.live} connected: ${[s.builtin ? 'the built-in scanner' : '', s.external ? `${s.external} external` : ''].filter(Boolean).join(' and ')}` : s.builtin_state.text);
      if (d) {
        set(lines[1], d.state === 'done' || d.state === 'ended' ? 'ok' : 'run', d.text);
        set(lines[2], d.hosts ? 'ok' : 'run', `${d.hosts} subdomain${d.hosts === 1 ? '' : 's'} found so far`);
        recent.textContent = d.recent.length ? `Latest: ${d.recent.join(', ')}` : '';
      } else { set(lines[1], '', 'No discovery was started (the first step was skipped).'); set(lines[2], '', ''); }
      const w = r.dwell;
      if (w.ready && !landing) {
        landing = true;
        say(d && d.hosts ? `${d.hosts} hosts found. Opening your dashboard.` : 'Opening your dashboard. Discovery carries on in the background.');
        setTimeout(() => leave(d && d.scan_id), 2500);
      } else if (!w.ready) {
        say(`${d ? d.text : ''} ${w.reason}`.trim());
      }
      const left = Math.max(0, (w.min_seconds || 0) - (w.elapsed || 0));
      wait.textContent = w.ready ? '' : `Giving discovery up to ${left} more second${left === 1 ? '' : 's'} so the dashboard opens with findings in it. ${w.reason}`;
      meter.style.width = `${Math.min(100, Math.round(((w.elapsed || 0) / Math.max(1, w.min_seconds || 1)) * 100))}%`;
      meter.parentElement.hidden = w.ready;
    };
    poll(); timer = setInterval(poll, 2500);
  },
};

document.getElementById('skip-all').addEventListener('click', async () => {
  stop();
  try { await welcome('POST', 'finish'); } catch (_) { /* open it anyway */ }
  window.location.href = '/cve/?skip=1';
});

(async () => {
  state = await welcome('GET', 'state');
  show(state.completed ? 0 : Math.max(0, STEPS.indexOf(state.next))); // a finished wizard reopens at the first step, with every saved value in place
})();
