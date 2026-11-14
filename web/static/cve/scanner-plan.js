// Which scanners run: the built-in scanner, your own Sentinels, or both (the three choices install.sh asks).
// askScannerPlan is the question the Update button asks first when there is one worth asking (the server decides: cveFeed/scanner_plan.py);
// mountScannerPlan is the "Which scanners run" control on the Sentinels page. The words come from the server, so the dialog, the page and the tests agree.
import { api, button, dialog, el, toast } from '/staticfiles/cve/ui.js';
import { fmtTime } from '/staticfiles/cve/prefs.js';

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
const DONE_SHOWN_MS = 5 * 60 * 1000;  // a "Done at" answer older than this is history, not news: the line goes back to saying what runs now
const DONE_CLEARS_MS = 20 * 1000;  // and one that was just seen clears itself after this long
const FAILED_SHOWN_MS = 24 * 3600 * 1000;
const POLL_MS = 4000;
const FAILURES_BEFORE_SAYING = 2;

const clock = (epoch) => fmtTime(new Date(epoch * 1000).toISOString(), false);

// The status line for what the server said: {text, kind} with kind 'busy' | 'ok' | 'err' | 'note'. Pure, so the tests read it without a page.
//   waiting: says what it waits on (the server works it out: cveFeed/scanner_plan.py waiting_on) and when it was asked;
//   done:    "Done at HH:MM" in the person's time zone, with what changed, until it clears (ctx.cleared) or is older than five minutes;
//   failed:  the host's reason and what to do, until the next Apply (a failure explains why nothing changed, so it is kept for a day);
//   else:    what runs now.
export function planLine(s, ctx = {}) {
  const now = ctx.now ?? Date.now();
  if (s.waiting) {
    const why = s.waiting_on ? s.waiting_on.text : 'If a scan is running it starts after the scan finishes.';
    return { text: `Applying the change. ${why}${s.asked_at ? ` Asked at ${clock(s.asked_at)}.` : ''}`, kind: 'busy' };
  }
  const a = s.applied;
  const age = a && a.at ? now - a.at * 1000 : null;
  if (a && !a.ok && (age === null || age <= FAILED_SHOWN_MS)) {
    return { text: `Not done${a.at ? ` (${clock(a.at)})` : ''}: ${a.note || 'the host gave no reason'}. What to do: open scanner-plan.log in the host's update state directory to see why, fix that, then press Apply again.`, kind: 'err' };
  }
  if (a && a.ok && age === null) return { text: `Done: ${a.note}`, kind: 'ok' };
  if (a && a.ok && age <= DONE_SHOWN_MS && ctx.cleared !== a.at) {
    const before = ctx.before && ctx.before !== a.plan ? ctx.before : null;
    const changed = before ? `changed from ${PLAN_WORDS[before]} to ${PLAN_WORDS[a.plan]}` : `now ${PLAN_WORDS[a.plan]}`;
    return { text: `Done at ${clock(a.at)}: ${changed}.${a.note ? ` The host says: ${a.note}.` : ''}`, kind: 'ok' };
  }
  return { text: `Now: ${PLAN_WORDS[s.plan]}.`, kind: 'note' };
}

const LINE_CLASS = { busy: 'msg busy', ok: 'msg ok', err: 'msg err', note: 'note' };

// The control on the Sentinels page. Does nothing for anyone who may not change it (the endpoint is for App Admins).
export async function mountScannerPlan(host) {
  let state;
  try { state = await api('GET', SETTINGS); } catch (_) { host.hidden = true; return; }
  let timer = null, clearTimer = null, failures = 0;
  let before = null;  // what ran when Apply was pressed, for "changed from ... to ..."
  let cleared = null;  // the answer (its time) already shown and cleared, so it does not come back
  let line = null;
  const show = ({ text, kind }) => { line.textContent = text; line.className = LINE_CLASS[kind]; };
  const draw = (s) => {
    host.textContent = '';
    host.hidden = false;
    host.append(el('h2', '', 'Which scanners run'));
    if (s.notice) host.append(el('p', 'msg', s.notice.text, { role: 'status' }));
    if (s.discovery_pin_notice) host.append(el('p', 'msg', s.discovery_pin_notice, { role: 'status' }));
    host.append(el('p', 'note', s.memory_line));
    const picked = planChoices(s.options, s.pending_plan || s.plan, 'plan-card');
    host.append(picked.group);
    line = el('p', 'note', '', { role: 'status' });
    const shown = planLine(s, { before, cleared });
    show(shown);
    clearTimeout(clearTimer);
    if (shown.kind === 'ok' && s.applied && s.applied.at && !s.waiting) {  // an answer clears itself: the line returns to what runs now
      const at = s.applied.at;
      clearTimer = setTimeout(() => { if (host.isConnected) { cleared = at; draw({ ...s }); } }, DONE_CLEARS_MS);
    }
    const go = button('Apply', async () => {
      const plan = picked.value();
      if (!plan) return;
      before = s.applied && s.applied.ok && s.applied.at ? s.applied.plan : s.plan;
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
        if (!s || !s.options) throw new Error('signed out');  // a login page answers 200 with no JSON: the old words must not stay
        failures = 0;
        draw(s);
        if (s.waiting) poll();
      } catch (e) {
        failures += 1;
        // the services restart while it is applied: keep trying, but say so instead of leaving the old words up as if they were current
        if (failures >= FAILURES_BEFORE_SAYING && line) {
          show(/signed out|\(40[13]\)/.test(e.message)
            ? { text: 'You are signed out, so this page cannot see whether the change was applied. Reload the page and sign in.', kind: 'err' }
            : { text: 'Cannot reach the server to see how the change is going (it restarts while a change is applied). Still trying.', kind: 'busy' });
        }
        if (!/signed out|\(40[13]\)/.test(e.message)) poll();
      }
    }, POLL_MS);
  };
  draw(state);
  if (state.waiting) poll();
}
