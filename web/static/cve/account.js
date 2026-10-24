import { api, badge, button, el, field, shortDate, text, toast } from '/staticfiles/cve/ui.js';

const view = document.getElementById('view');

function card(title, ...kids) {
  const c = el('section', 'card');
  c.append(el('h2', '', title), ...kids);
  c.firstChild.style.marginBottom = '12px';
  return c;
}
const rows = (pairs) => {
  const dl = el('dl', 'node-rows');
  pairs.filter(([, v]) => v !== '' && v != null).forEach(([k, v]) => dl.append(el('dt', '', k), el('dd', '', String(v))));
  return dl;
};
const linkButton = (label, href) => Object.assign(el('a', 'btn ghost sm', label), { href, style: 'display:inline-flex;align-items:center;text-decoration:none' });
const codeInput = () => text('', { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '20' });

// Two-step sign-in, managed in place: start (secret + QR), confirm with a code, show recovery codes once; or turn off with a code.
function twoStep(me) {
  const box = el('div', 'two-step');
  const status = el('p', 'note', me.mfa_enabled ? 'Two-step sign-in is on.'
    : (me.mfa_required ? 'Your organization requires two-step sign-in. Turn it on now to keep using CVEngine.' : 'Two-step sign-in is off.'));
  box.append(el('h3', '', 'Two-step sign-in'), status);

  if (me.mfa_enabled) {
    if (me.mfa_required) {
      box.append(el('p', 'note', 'Your organization requires it, so it cannot be turned off here.'));
      return box;
    }
    box.append(button('Turn off two-step sign-in', async () => {
      const code = codeInput();
      const form = el('div', 'two-step-form');
      form.append(field('Code from your authenticator app, or a recovery code', code), button('Turn off', async () => {
        await api('POST', '/cve/api/account/mfa/disable', { code: code.value });
        toast('Two-step sign-in is off'); await draw();
      }));
      box.lastChild.replaceWith(form);
      code.focus();
    }, 'btn ghost sm'));
    return box;
  }

  box.append(button('Turn on two-step sign-in', async () => {
    const { secret, uri } = await api('POST', '/cve/api/account/mfa/start');
    const form = el('div', 'two-step-form');
    const qr = el('div', 'qr', null, { role: 'img', 'aria-label': 'QR code for authenticator setup' });
    if (window.qrcode) {
      const q = window.qrcode(0, 'M'); q.addData(uri); q.make();
      qr.innerHTML = q.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
    }
    const code = codeInput();
    form.append(
      el('p', 'note', 'Scan the QR code with an authenticator app, then enter the 6-digit code it shows.'),
      qr,
      el('p', 'note', 'Or enter this key manually:'), el('code', 'cve-id secret-key', secret),
      field('6-digit code', code),
      button('Confirm and turn on', async () => {
        const res = await api('POST', '/cve/api/account/mfa/enable', { code: code.value });
        await draw();
        showRecoveryCodes(res.recovery_codes);
      }));
    box.lastChild.replaceWith(form);
    code.focus();
  }, me.mfa_required ? 'btn sm' : 'btn ghost sm'));
  return box;
}

function showRecoveryCodes(codes) {
  const security = document.getElementById('security');
  if (!security || !codes || !codes.length) return;
  const note = el('div', 'recovery');
  note.append(el('h3', '', 'Recovery codes'),
    el('p', 'note', 'Save these now. Each works once if you lose your phone. They are not shown again.'),
    el('pre', 'recovery-codes', codes.join('\n')));
  security.querySelector('.two-step').after(note);
  toast('Two-step sign-in is on');
}

async function draw() {
  const me = await api('GET', '/cve/api/account/me');
  view.textContent = '';
  if (me.must_change_password) {
    view.append(Object.assign(el('div', 'msg err'), { textContent: 'An administrator gave you a temporary password. Choose your own below to continue.', style: 'grid-column:1/-1;margin:0' }));
  }
  const first = text(me.first_name, { autocomplete: 'given-name' });
  const last = text(me.last_name, { autocomplete: 'family-name' });
  const email = text(me.email, { type: 'email', autocomplete: 'email' });
  const profile = card('Profile',
    rows([['Account name', me.username], ['Role', me.role], ['Member since', shortDate(me.date_joined)], ['Last sign-in', shortDate(me.last_login)]]),
    el('div', '', null, { style: 'height:12px' }),
    field('First name', first), field('Last name', last), field('Email', email),
    button('Save profile', async () => {
      await api('PATCH', '/cve/api/account/profile', { first_name: first.value, last_name: last.value, email: email.value });
      toast('Profile saved'); await draw();
    }));

  const access = el('div');
  if (!me.access.length) access.append(el('p', 'note', 'You are not in any organization or project yet. Ask an administrator to add you.'));
  me.access.forEach((a) => {
    const row = el('div', 'access-row');
    row.append(el('span', 'kind', a.scope.toLowerCase()), el('span', '', a.name), badge(a.role));
    access.append(row);
  });
  const reach = card('What you can reach', access);

  const current = text('', { type: 'password', autocomplete: 'current-password' });
  const next = text('', { type: 'password', autocomplete: 'new-password' });
  const again = text('', { type: 'password', autocomplete: 'new-password' });
  const security = card('Security',
    twoStep(me),
    el('hr', '', null, { style: 'border:0;border-top:1px solid var(--line);margin:16px 0' }),
    el('h3', '', 'Password'),
    field('Current password', current), field('New password', next, 'At least 8 characters, not too common, not all digits.'), field('Repeat new password', again),
    button('Change password', async () => {
      if (next.value !== again.value) throw new Error('The two new passwords do not match.');
      await api('POST', '/cve/api/account/password', { current: current.value, new: next.value });
      toast('Password changed');
      if (me.must_change_password) window.location.href = '/cve/';
      else await draw();
    }));
  security.id = 'security';
  const apiCard = card('API tokens',
    el('p', 'note', `${me.tokens} active token${me.tokens === 1 ? '' : 's'}. Tokens let scripts and AI agents act as you.`),
    linkButton('Manage API tokens', '/cve/agents/'));

  // Two independent columns, so a tall card on one side never pushes the other side's cards down.
  const left = el('div', 'acct-col');
  left.append(profile, security);
  const right = el('div', 'acct-col');
  right.append(reach, apiCard);
  view.append(left, right);
  if (window.location.hash === '#security') security.scrollIntoView({ block: 'start' });
}
draw().catch((err) => view.append(el('p', 'msg err', err.message)));
