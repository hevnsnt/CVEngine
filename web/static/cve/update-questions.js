// "A few questions about this update" (cveFeed/setup_questions.py): one form. Each question that costs money or changes what is scanned has its choices and what
// each one does; "Save answers" saves every question on the page in one request (POST /cve/api/settings/setup_questions, which carries each answer out with the
// Settings handler of its feature) and "Decide later" leaves everything off. Every word from the server is set with textContent.
import { api, el, toast } from '/staticfiles/cve/ui.js';

const API = '/cve/api/settings/setup_questions';
const root = document.getElementById('uq');
const DASHBOARD = '/cve/?skip=1';

function card(q) {
  const box = el('section', 'card uq-card', null, { 'aria-labelledby': `uq-${q.key}` });
  box.append(el('h2', '', q.title, { id: `uq-${q.key}` }), el('p', 'note', q.text));
  if (!q.applies) {
    box.append(el('p', 'note', q.why_not));
    return { box, read: () => null };
  }
  if ((q.new_lines || []).length) box.append(el('p', 'note uq-new', `${q.new_lines.length} new line${q.new_lines.length === 1 ? '' : 's'} since your last answer: ${q.new_lines.join(', ')}. It stays off until you choose.`));
  if (q.facts.length) {
    const list = el('ul', 'uq-facts');
    q.facts.forEach((f) => list.append(el('li', '', f)));
    box.append(list);
  }
  const group = el('fieldset', 'uq-choices');
  group.append(el('legend', 'visually-hidden', q.title));
  const start = q.state === 'answered' && q.answer ? q.answer : q.state === 'decided' ? q.current : q.safe_default;
  q.choices.forEach((c) => {
    const id = `uq-${q.key}-${c.value}`;
    const input = el('input', '', null, { type: 'radio', name: `uq-${q.key}`, value: c.value, id });
    input.checked = c.value === start;
    const row = el('label', 'uq-opt', null, { for: id });
    const words = el('span', 'uq-words');
    const head = el('b', '', c.label);
    if (c.tag) head.append(' ', el('span', 'uq-tag', c.tag));
    words.append(head, el('span', 'note uq-effect', c.effect));
    row.append(input, words);
    group.append(row);
  });
  box.append(group);
  const foot = el('p', 'note uq-later');
  foot.append('Change this later in ', el('a', '', q.link_text, { href: q.link }), '.');
  box.append(foot);
  // a question already set in Settings is sent again only when the choice here differs from what is set
  const read = () => {
    const picked = group.querySelector('input:checked');
    if (!picked) return null;
    return q.state === 'decided' && picked.value === q.current ? null : picked.value;
  };
  return { box, read };
}

function nextSteps(next) {
  const box = el('section', 'card uq-card uq-next', null, { 'aria-labelledby': 'uq-next' });
  box.append(el('h2', '', 'One more step', { id: 'uq-next' }));
  next.notes.forEach((n) => box.append(el('p', 'note', n)));
  const list = el('ul', 'uq-steps');
  next.steps.forEach((s) => { const li = el('li'); li.append(el('a', '', s.text, { href: s.url })); list.append(li); });
  box.append(list, el('a', 'btn', 'Open the dashboard', { href: DASHBOARD }));
  return box;
}

async function draw() {
  const data = await api('GET', API);
  root.querySelectorAll(':scope > :not([name=csrfmiddlewaretoken])').forEach((n) => n.remove());
  (data.notes || []).forEach((n) => root.append(el('p', 'note uq-info', n)));
  const cards = data.questions.map(card);
  cards.forEach((c) => root.append(c.box));
  const actions = el('div', 'uq-actions');
  const save = el('button', 'btn', 'Save answers', { type: 'button' });
  const later = el('button', 'btn ghost', 'Decide later', { type: 'button' });
  const why = el('p', 'note', 'Everything stays off, and a reminder stays at the top of the app until you answer.');
  save.onclick = async () => {
    const answers = {};
    cards.forEach((c, i) => { const v = c.read(); if (v) answers[data.questions[i].key] = v; });
    save.disabled = later.disabled = true;
    try {
      const out = Object.keys(answers).length ? await api('POST', API, { answers }) : data;
      const next = (out.questions.find((q) => q.key === 'scan_from') || {}).next;
      if (next && answers.scan_from) {
        root.querySelectorAll(':scope > :not([name=csrfmiddlewaretoken])').forEach((n) => n.remove());
        root.append(nextSteps(next));
        window.scrollTo(0, 0);
      } else {
        window.location.href = DASHBOARD;
      }
    } catch (err) { toast(err.message, true); save.disabled = later.disabled = false; }
  };
  later.onclick = async () => {
    save.disabled = later.disabled = true;
    try { await api('POST', API, { later: true }); toast('Nothing was switched on. You can answer from the reminder at the top of the app.'); window.location.href = DASHBOARD; } catch (err) { toast(err.message, true); save.disabled = later.disabled = false; }
  };
  actions.append(save, later, why);
  root.append(actions);
}

draw().catch((err) => root.append(el('p', 'msg err', err.message, { role: 'alert' })));
