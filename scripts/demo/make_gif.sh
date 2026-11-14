#!/usr/bin/env bash
# make_gif.sh: rebuilds the README tour (docs/images/cvengine-tour-1.4.gif) from a fresh seed. ONE COMMAND, from the repo root, with Postgres and Redis up, the
# settings environment set (the same one scripts/ci_ui_gates.sh needs), an EMPTY database that has been migrated, `npm root -g` holding playwright with Chromium
# installed, and ffmpeg on the path:
#
#     scripts/demo/make_gif.sh                      # seed, start the app, record the tour, write docs/images/cvengine-tour-1.4.gif
#     scripts/demo/make_gif.sh OUT.gif              # the same, to another file
#     scripts/demo/make_gif.sh IN.webm OUT.gif      # only turn a recording into a GIF (env: START seconds to skip, SPEED play-back factor (1.6), WIDTH, FPS, COLORS)
#
# The seed is scripts/demo/seed_demo.py (the fictional company Acme Corp: made-up domains, documentation-range and private addresses) plus scripts/demo/seed_tour_projects.py
# (five more made-up companies, so the All projects graph has six constellations; the CI UI gates do not run it), the recording is
# scripts/demo/record_tour.js, and the live CVE moment is scripts/demo/stage_live.py, which the recording starts while it films. Never run it against a real install:
# the seed creates an App Admin with a known password. The GIF is WIDTH wide (880) at FPS frames a second (10), 36-colour palette-optimised, and loops. Waiting-for-page stretches of the recording are cut (cuts.json).
set -euo pipefail
cd "$(dirname "$0")/../.."
WIDTH=${WIDTH:-880}; COLORS=${COLORS:-36}; FPS=${FPS:-10}; START=${START:-0}; SPEED=${SPEED:-1.6}

to_gif() {  # to_gif IN.webm OUT.gif: the stretches the recording marked as waiting for a page (cuts.json beside it) are left out, nothing else is touched
  local cuts="$(dirname "$1")/cuts.json" keep=""
  if [[ -f $cuts ]]; then
    keep=$(node - "$cuts" <<'JS'
const c = JSON.parse(require('fs').readFileSync(process.argv[2])).filter((r) => r[1] - r[0] > 0.15).map((r) => `between(t,${r[0].toFixed(2)},${r[1].toFixed(2)})`);
process.stdout.write(c.length ? `select='not(${c.join('+')})',` : '');
JS
)
  fi
  ffmpeg -y -loglevel error -ss "$START" -i "$1" -vf "fps=$FPS,${keep}setpts=N/($FPS*$SPEED)/TB,scale=$WIDTH:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=$COLORS:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" -loop 0 "$2"
  ls -la "$2"
}

if [[ ${1:-} == *.webm ]]; then to_gif "$1" "${2:?usage: make_gif.sh IN.webm OUT.gif}"; exit 0; fi

OUT_GIF=${1:-docs/images/cvengine-tour-1.4.gif}
PORT=${TOUR_PORT:-28171}
WORK=${TOUR_WORK:-$(mktemp -d)}
export BASE="http://127.0.0.1:$PORT" PROJECT=acme-corp OUT="$WORK/rec" STAGE_CWD="$PWD/web"
export STAGE='python3 manage.py shell < ../scripts/demo/stage_live.py'
export NODE_PATH=${NODE_PATH:-$(npm root -g)}

(cd web && python3 manage.py shell < ../scripts/demo/seed_demo.py && python3 manage.py shell < ../scripts/demo/seed_tour_projects.py)
(cd web && exec python3 manage.py runserver "127.0.0.1:$PORT" --insecure --noreload > "$WORK/server.log" 2>&1) &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do curl -fsS -o /dev/null "$BASE/login/" && break; sleep 1; done
curl -fsS -o /dev/null "$BASE/login/" || { cat "$WORK/server.log"; echo "the app did not start"; exit 1; }

node scripts/demo/record_tour.js
video=$(ls -t "$OUT"/*.webm | head -1)
mkdir -p "$(dirname "$OUT_GIF")"
to_gif "$video" "$OUT_GIF"
echo "recording kept in $WORK"
