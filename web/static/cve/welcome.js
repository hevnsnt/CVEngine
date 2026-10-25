// First-run guided setup: organization, project, AI model, first target, optional search-engine keys. Every step is shown; what already exists is
// filled in, so a finished step is one click on Continue.
const root = document.getElementById('wizard');
const csrf = root.querySelector('[name=csrfmiddlewaretoken]').value;
const stepBox = document.getElementById('step');
const dots = document.getElementById('dots');
const STEPS = ['welcome', 'org', 'project', 'ai', 'target', 'keys'];
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
let followScan = null; // the discovery the target step started, followed on the last step and from the dashboard
let poller = null;

function drawDots() {
  dots.textContent = '';
  STEPS.forEach((_, i) => dots.append(el('i', i <= index ? 'on' : '')));
}

function show(i) {
  clearInterval(poller);
  index = i;
  drawDots();
  stepBox.textContent = '';
  const node = el('div', 'step');
  stepBox.append(node);
  steps[STEPS[i]](node);
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
  if (skip) { const s = el('button', 'skip', skip.label, { type: 'button' }); s.onclick = skip.onClick; actions.append(s); }
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
  const first = f.querySelector('input,select');
  if (first) first.focus();
}

const steps = {
  welcome(node) {
    node.append(el('h1', '', 'Welcome to CVEngine'),
      el('p', 'lead', 'AI-first vulnerability management. A few quick steps and you will be on your way.'));
    const list = el('ul', 'points');
    [['1', 'Name your organization and first project', 'Findings stay organized, teammates can be added later.'],
     ['2', 'Connect your AI model', 'It reads the CVE feed, checks your inventory, and writes and runs checks.'],
     ['3', 'Add a target', 'Enter a domain and discovery starts immediately.'],
     ['4', 'Optional: search-engine keys', 'Shodan and friends find more while you finish. Skip it any time.']].forEach(([n, t, d]) => {
      const li = el('li'); const c = el('div'); c.append(el('div', '', t, { style: 'font-weight:650;font-size:15px' }), el('span', '', d));
      li.append(el('b', '', n), c); list.append(li);
    });
    node.append(list);
    const actions = el('div', 'actions');
    actions.append(el('span', 'grow'));
    const go = el('button', 'btn', 'Get started', { type: 'button' });
    go.onclick = () => show(1);
    actions.append(go);
    node.append(actions);
  },

  org(node) {
    const name = el('input', '', null, { value: state.org && state.org.named ? state.org.name : '', placeholder: 'Acme Security', autocomplete: 'organization', required: '' });
    form(node, {
      title: 'Name your organization', lead: 'This is the top level. Your projects and teammates live inside it.',
      body: [field('Organization name', name)], primary: 'Continue',
      onSubmit: async () => {
        const known = state.org && state.org.named ? state.org.name : '';
        if (known && name.value.trim() === known) { next(); return; } // already set: nothing to save
        state = await welcome('POST', 'org', { name: name.value });
        next();
      },
    });
  },

  project(node) {
    const name = el('input', '', null, { value: state.project && state.project.named ? state.project.name : '', placeholder: 'Production', required: '' });
    form(node, {
      title: 'Create your first project', lead: 'A project holds your targets, scans and findings. Nothing is shared between projects.',
      body: [field('Project name', name, 'Examples: Production, Client A, Lab')], primary: 'Continue',
      onSubmit: async () => {
        const known = state.project && state.project.named ? state.project.name : '';
        if (known && name.value.trim() === known) { next(); return; }
        state = await welcome('POST', 'project', { name: name.value });
        next();
      },
    });
  },

  ai(node) {
    const key = el('input', '', null, { type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: 'sk-ant-...  or  sk-...' });
    const hint = el('p', 'note', 'Paste an Anthropic, OpenAI or OpenRouter key and we will detect which one it is (Ollama and vLLM are set up in Settings). It is stored in your database and never shown again.', { style: 'margin:6px 0 0' });
    let timer;
    key.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        if (!key.value.trim()) { hint.textContent = 'Paste an Anthropic or OpenAI key and we will detect which one it is.'; return; }
        const r = await api('POST', '/cve/api/setup/detect', { key: key.value }).catch(() => ({}));
        hint.textContent = r.provider ? `That looks like an ${NAMES[r.provider]} key.` : 'We do not recognize that key. You can keep going and pick a provider in Settings.';
      }, 250);
    });
    if (state.ai_ready) { key.placeholder = 'Connected. Paste a new key only to replace it.'; hint.textContent = 'An AI model is already connected. Continue, or paste a new key to replace it.'; }
    const wrap = el('div', 'field'); wrap.append(el('label', '', 'API key', { for: 'ai-key' }), key, hint); key.id = 'ai-key';
    form(node, {
      title: 'Connect your AI model', lead: 'This is what confirms which hosts are really exposed and writes checks for new CVEs.',
      body: [wrap], primary: state.ai_ready ? 'Continue' : 'Verify and continue',
      skip: { label: 'Skip for now', onClick: next },
      onSubmit: async () => {
        if (!key.value.trim() && state.ai_ready) { next(); return; } // a model is already connected
        if (!key.value.trim()) throw new Error('Paste a key, or choose "Skip for now".');
        const r = await api('POST', '/cve/api/setup/save', { key: key.value });
        key.value = '';
        if (r.needs_model) { hint.textContent = `Connected to ${NAMES[r.provider] || r.provider}. Choose its model in Settings > AI model, then turn it on.`; next(); return; }
        state.ai_ready = true;
        hint.textContent = `Connected to ${NAMES[r.provider] || r.provider}.`;
        next();
      },
    });
  },

  target(node) {
    const value = el('input', '', null, { placeholder: 'example.com, 203.0.113.10 or 10.0.0.0/28', required: '', spellcheck: 'false', autocapitalize: 'none' });
    const auth = el('input', '', null, { type: 'checkbox', id: 'authorized' });
    const authWrap = el('label', 'check', null, { for: 'authorized' });
    authWrap.append(auth, document.createTextNode('I am authorized to test this target.'));
    const hint = el('div', 'live-hint');
    hint.append(el('span', 'live', 'live'), document.createTextNode('Discovery starts with public data sources only and shows up on your dashboard as it runs.'));
    form(node, {
      title: 'Add your first target', lead: 'A domain, IP address or range. Start with something you own.',
      body: [field('Target', value), authWrap, hint], primary: 'Start discovery',
      skip: { label: 'Skip for now', onClick: finish },
      onSubmit: async () => {
        if (!auth.checked) throw new Error('Please confirm you are authorized to test this target.');
        const r = await welcome('POST', 'target', { value: value.value, authorized: true, project: state.project && state.project.slug });
        followScan = r.scan_id || null;
        next(); // discovery is already running: the last step shows it while the optional keys are offered
      },
    });
  },

  keys(node) {
    const offered = [['shodan', 'Shodan', 'Hosts, open ports and services Shodan has already seen'],
                     ['virustotal', 'VirusTotal', 'Subdomains VirusTotal knows about'],
                     ['securitytrails', 'SecurityTrails', 'Historical DNS and subdomains']];
    const inputs = {};
    const body = offered.map(([service, label, help]) => {
      const input = el('input', '', null, { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'Paste a key, or leave empty' });
      inputs[service] = input;
      return field(label, input, help);
    });
    const progress = el('div', 'live-hint', null, { 'aria-live': 'polite' });
    const dot = el('span', 'live', 'live');
    const text = document.createTextNode('Discovery is starting...');
    progress.append(dot, text);
    const open = () => { window.location.href = followScan ? `/cve/?follow=${followScan}` : '/cve/'; };
    const done = async () => { await welcome('POST', 'finish'); open(); };
    form(node, {
      title: 'Optional: add search-engine keys',
      lead: 'Discovery is already running with free public sources. Keys let it ask more services, and apply from the next scan on (Settings > API keys has the full list). Add them while the first results come in, or skip.',
      body: [...body, progress], primary: 'Save and finish',
      skip: { label: 'Skip', onClick: () => done().catch((err) => { text.textContent = err.message; }) },
      onSubmit: async () => {
        const keys = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value.trim()]).filter(([, v]) => v));
        if (Object.keys(keys).length) await welcome('POST', 'keys', { keys, project: state.project && state.project.slug });
        Object.values(inputs).forEach((i) => { i.value = ''; });
        await done();
      },
    });
    const poll = async () => {
      if (!followScan) { text.textContent = 'Your target is added. Discovery will start shortly.'; return; }
      try {
        const r = await api('GET', `/cve/api/discovery?scan=${followScan}`);
        const scan = r.scan;
        if (!scan) return;
        const c = r.counts || {};
        const found = `${c.hosts || 0} hosts, ${c.ips || 0} IP addresses`;
        text.textContent = scan.status === -1
          ? `Waiting for a free scanner${scan.queue_position ? ` (${scan.queue_position} ahead)` : ''}...`
          : scan.status === 1 ? `Discovering ${scan.target}: ${found} so far` : scan.status === 2 ? `Discovery of ${scan.target} finished: ${found}` : `Discovery of ${scan.target} ended early: ${found}`;
        if (scan.status !== -1 && scan.status !== 1) clearInterval(poller);
      } catch (_) { /* the next poll tries again */ }
    };
    poll();
    poller = setInterval(poll, 3000);
  },
};

async function finish() {
  await welcome('POST', 'finish');
  window.location.href = '/cve/';
}

(async () => {
  state = await welcome('GET', 'state');
  show(0);
})();
