// "A few questions about this update" (cveFeed/setup_questions.py): each question that costs money or changes what is scanned, with its choices and what
// each one does. An answer goes through the Settings API (POST /cve/api/settings/setup_questions), which carries it out with the Settings handler of the feature.
// "Decide later" leaves everything off. Every word from the server is set with textContent.
import { api, el, toast } from '/staticfiles/cve/ui.js';

const API = '/cve/api/settings/setup_questions';
const root = document.getElementById('uq');
const STATES = { pending: 'Not answered', later: 'Decide later', answered: 'Answered', decided: 'Set in Settings' };

function card(q, reload) {
  const box = el('section', 'card uq-card', null, { 'aria-labelledby': `uq-${q.key}` });
  const head = el('h2', '', q.title, { id: `uq-${q.key}` });
  head.append(' ', el('span', `uq-state ${q.state}`, STATES[q.state] || ''));
  box.append(head, el('p', 'note', q.text));
  if (!q.applies) {
    box.append(el('p', 'note', q.why_not));
    return box;
  }
  const group = el('fieldset', 'plan-choices uq-choices');
  group.append(el('legend', 'note', 'Choose one'));
  const start = q.state === 'answered' && q.answer ? q.answer : q.state === 'decided' ? q.current : q.safe_default;
  q.choices.forEach((c) => {
    const id = `uq-${q.key}-${c.value}`;
    const input = el('input', '', null, { type: 'radio', name: `uq-${q.key}`, value: c.value, id });
    input.checked = c.value === start;
    const row = el('label', 'plan-opt uq-opt', null, { for: id });
    const words = el('span', '');
    words.append(el('b', '', c.safe ? `${c.label} (the safe choice)` : c.label), el('span', 'note uq-effect', c.effect));
    row.append(input, words);
    group.append(row);
  });
  box.append(group);
  if (q.state === 'decided') box.append(el('p', 'note', `You already chose this in ${q.link_text}. Saving here does the same as changing it there.`));
  const actions = el('div', 'actions');
  const save = el('button', 'btn', 'Save my answer', { type: 'button' });
  save.onclick = async () => {
    const picked = group.querySelector('input:checked');
    if (!picked) return toast('Choose one first.', true);
    save.disabled = true;
    try { await api('POST', API, { key: q.key, answer: picked.value }); toast('Saved.'); await reload(); } catch (err) { toast(err.message, true); } finally { save.disabled = false; }
  };
  actions.append(save, el('a', 'btn ghost', q.link_text, { href: q.link }));
  box.append(actions);
  return box;
}

async function draw() {
  const data = await api('GET', API);
  root.querySelectorAll(':scope > :not([name=csrfmiddlewaretoken])').forEach((n) => n.remove());
  data.questions.forEach((q) => root.append(card(q, draw)));
  const foot = el('div', 'actions uq-foot');
  if (data.pending) {
    const later = el('button', 'btn ghost', 'Decide later', { type: 'button' });
    later.onclick = async () => {
      later.disabled = true;
      try { await api('POST', API, { later: true }); toast('Nothing was switched on. The questions stay in Settings.'); await draw(); } catch (err) { toast(err.message, true); later.disabled = false; }
    };
    foot.append(later, el('span', 'note', 'Everything stays off, and a reminder stays at the top of the app.'));
  }
  foot.append(el('a', 'btn', 'Open the dashboard', { href: '/cve/?skip=1' }));
  root.append(foot);
}

draw().catch((err) => root.append(el('p', 'msg err', err.message, { role: 'alert' })));
