#!/usr/bin/env bash
# make_gif.sh INPUT.webm OUTPUT.gif [WIDTH] [FPS]  (env: START seconds to skip, SPEED play-back factor): a palette-optimised GIF of a recording (the README tour is 960 wide at 10 frames a second)
set -euo pipefail
in=$1; out=$2; width=${3:-960}; fps=${4:-10}; start=${START:-0}; speed=${SPEED:-1}
ffmpeg -y -loglevel error -ss "$start" -i "$in" -vf "setpts=PTS/$speed,fps=$fps,scale=$width:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" -loop 0 "$out"
ls -la "$out"
