import assert from 'node:assert/strict';
import {test} from 'node:test';

import * as logic from '../static/cve/config-maxxing-logic.js';

// Words for people on the Settings page: no code name, no environment variable name and no ".env" in the sentence a person reads.
// The technical name stays available, behind a Details line (the `detail` / `serverSetting` values below).
const field = {key: 'stage_parallel', label: 'Chunks', default: 4, value: 6, source: 'environment', env_name: 'CVENGINE_STAGE_PARALLEL', env_value: 6};
const bare = (s) => assert.doesNotMatch(String(s), /CVENGINE_|\.env\b|configMaxxing|environment variable/i, String(s));

test('the section keeps its name, with a plain sentence saying what it is for', () => {
  assert.equal(logic.SECTION_LABEL, 'configMaxxing');
  assert.match(logic.WARNING_TEXT, /^configMaxxing: advanced performance settings\./);
});

test('where a number comes from is said in plain words; the variable name is the Details line', () => {
  bare(logic.sourceLabel(field));
  logic.originLines(field).forEach(bare);
  assert.match(logic.serverSetting(field), /CVENGINE_STAGE_PARALLEL=6/);
  assert.match(logic.serverSetting({...field, env_value: null}), /CVENGINE_STAGE_PARALLEL is not set/);
});

test('auto-tuning help and notices do not send a person to a file on the server', () => {
  bare(logic.AUTOTUNE_OFF_HELP);
  bare(logic.AUTOTUNE_INTRO);
  bare(logic.modeNotice({killed: true}));
  assert.match(logic.modeDetail({killed: true}), /CVENGINE_AUTOTUNE=0/);
  const line = logic.autoTuneLine({value: 1, autotune: {managed: true, pinned: true, pinned_by: null, pinned_env: 'HEAVY_MAX_NMAP=1'}}, 'auto');
  bare(line.text);
  assert.match(line.detail, /HEAVY_MAX_NMAP=1/);
});

test('a cap warning names the server, not the environment', () => {
  bare(logic.softWarning({...field, caution: "cap", min: 1, max: 1000, default: 4}, "200"));
});
