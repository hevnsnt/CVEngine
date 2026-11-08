// Which scanners run: the built-in scanner, your own Sentinels, or both (the three choices install.sh asks).
// askScannerPlan is the question the Update button asks first when there is one worth asking (the server decides: cveFeed/scanner_plan.py);
// mountScannerPlan is the "Which scanners run" control on the Sentinels page. The words come from the server, so the dialog, the page and the tests agree.
import { api, button, dialog, el, toast } from '/staticfiles/cve/ui.js';

const SETTINGS = '/cve/api/settings/scanner_plan';

// A group of the three options as radios, each a 44px-high label. `selected` is the value that starts checked. Returns the group and a reader.
export function planChoices(options, selected, name = 'scanner-plan') {
  const group = el('fieldset', 'plan-choices');
  group.append(el('legend', 'note', 'Scanners that run'));
  const inputs = [];
  options.forEach((opt, i) => {
    const input = el('input', '', null, { type: 'radio', name, value: opt.value, id: `${name}-${opt.value}` });
    input.checked = opt.value === selected;
    inputs.push(input);
    const row = el('label', 'plan-opt', null, { for: `${name}-${opt.value}` });
    row.append(input, el('span', '', opt.label));
    group.append(row);
  });
  return { group, inputs, value: () => (inputs.find((i) => i.checked) || {}).value || null };
}

// Resolves to 'internal' | 'both' | 'external', or null when the person cancelled (nothing is started).
export function askScannerPlan(choice) {
  return new Promise((resolve) => {
    let answer = null;
    const d = dialog('Which scanners should run?', (body, close) => {
      body.append(el('p', 'note', choice.memory_line, { style: 'font-size:14px' }));
      body.append(el('p', 'note', 'Pick what this server should scan with. You can change it later in Settings > Sentinels.', { style: 'font-size:14px' }));
      const picked = planChoices(choice.options, choice.recommended);
      body.append(picked.group);
      const actions = el('div', 'actions');
      const no = el('button', 'btn ghost', 'Cancel', { type: 'button' });
      no.onclick = close;
      const yes = el('button', 'btn', 'Update now', { type: 'button' });
      yes.onclick = () => { answer = picked.value(); close(); };
      actions.append(no, yes);
      body.append(actions);
      setTimeout(() => (picked.inputs.find((i) => i.checked) || yes).focus(), 0);
    });
    d.addEventListener('close', () => resolve(answer));
  });
}

const PLAN_WORDS = { internal: 'the built-in scanner only', both: 'your Sentinels and the built-in scanner', external: 'your own Sentinels only' };

// The control on the Sentinels page. Does nothing for anyone who may not change it (the endpoint is for App Admins).
export async function mountScannerPlan(host) {
  let state;
  try { state = await api('GET', SETTINGS); } catch (_) { host.hidden = true; return; }
  let timer = null;
  const draw = (s) => {
    host.textContent = '';
    host.hidden = false;
    host.append(el('h2', '', 'Which scanners run'));
    if (s.notice) host.append(el('p', 'msg', s.notice.text, { role: 'status' }));
    host.append(el('p', 'note', s.memory_line));
    const picked = planChoices(s.options, s.pending_plan || s.plan, 'plan-card');
    host.append(picked.group);
    const line = el('p', 'note', '', { role: 'status' });
    if (s.waiting) line.textContent = 'Applying the change. If a scan is running it starts after the scan finishes.';
    else if (s.applied) line.textContent = `${s.applied.ok ? 'Done' : 'Not done'}: ${s.applied.note}`;
    else line.textContent = `Now: ${PLAN_WORDS[s.plan]}.`;
    const go = button('Apply', async () => {
      const plan = picked.value();
      if (!plan) return;
      draw(await api('POST', SETTINGS, { plan }));
      toast('Asked the host to apply it');
      poll();
    });
    host.append(go, document.createTextNode(' '), line);
  };
  const poll = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!host.isConnected) return;
      try {
        const s = await api('GET', SETTINGS);
        draw(s);
        if (s.waiting) poll();
      } catch (_) { poll(); }  // the services restart while it is applied: keep trying
    }, 4000);
  };
  draw(state);
  if (state.waiting) poll();
}
