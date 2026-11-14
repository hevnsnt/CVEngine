#!/usr/bin/env bash
# Browser gates on the seeded demo data: starts the app, seeds it (scripts/demo/seed_demo.py then seed_ui_gate.py), and runs the ui_* gate scripts in headless
# Chromium. Used by the "UI gates" job of .github/workflows/build-pr.yml; runs the same way on a developer machine (Postgres and Redis up, the settings
# environment set, `playwright install chromium` done):
#
#     scripts/ci_ui_gates.sh            # every gate, then a summary; exit 1 if any failed
#
# A gate that fails prints its output and is listed in the summary; the others still run. A gate is never switched off here: one that cannot pass is
# named in KNOWN_FAILING with the reason, still runs, and its failure is reported but does not fail the job (so a regression elsewhere in it is still visible).
set -u
cd "$(dirname "$0")/.."
PORT=${UI_GATE_PORT:-28151}
export BASE="http://127.0.0.1:$PORT" PROJECT=acme-corp EMPTY_PROJECT=harbor-foods USER_NAME=admin PASSWORD=demo-Tour-2026
KNOWN_FAILING=" ui_glance_layout "   # needs CVE matches that carry a template check and a tested time, which the demo seed does not write (docs: scripts/ui_glance_layout.py)
LOG=${UI_GATE_LOGS:-/tmp/ui-gates}; mkdir -p "$LOG"

(cd web && python manage.py shell < ../scripts/demo/seed_demo.py > "$LOG/seed1.log" 2>&1 && python manage.py shell < ../scripts/demo/seed_ui_gate.py > "$LOG/seed2.log" 2>&1) || { cat "$LOG"/seed*.log; echo "seeding failed"; exit 1; }
(cd web && exec python manage.py runserver "127.0.0.1:$PORT" --insecure --noreload > "$LOG/server.log" 2>&1) &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
for _ in $(seq 1 60); do curl -fsS -o /dev/null "$BASE/login/" && break; sleep 1; done
curl -fsS -o /dev/null "$BASE/login/" || { cat "$LOG/server.log"; echo "the app did not start"; exit 1; }

failed=""; known=""
run() {
  name=$1; shift
  echo "=== $name"
  if timeout "${GATE_TIMEOUT:-900}" "$@" > "$LOG/$name.log" 2>&1; then
    echo "ok: $name ($(grep -c '^ok' "$LOG/$name.log" || true) checks)"
  else
    grep -E '^(FAIL|UNDER)|Traceback|Error' "$LOG/$name.log" | head -40
    if [[ "$KNOWN_FAILING" == *" $name "* ]]; then known="$known $name"; else failed="$failed $name"; fi
  fi
}
run ui_first_screen python scripts/ui_first_screen.py
run ui_list_viewport python scripts/ui_list_viewport.py
run ui_touchcheck python scripts/ui_touchcheck.py "$LOG/touch.json"
run ui_glance_layout python scripts/ui_glance_layout.py
run ui_contrast python scripts/ui_contrast.py
echo "--- failed:${failed:- none}; known failing (see KNOWN_FAILING):${known:- none}"
[ -z "$failed" ]
