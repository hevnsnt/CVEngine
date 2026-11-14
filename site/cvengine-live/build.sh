#!/usr/bin/env bash
# Wraps src/page.html (the page content) in a full HTML document at public/index.html.
set -euo pipefail
cd "$(dirname "$0")"
{
  printf '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
  printf '<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%%}[hidden]{display:none!important}</style>\n'
  printf '</head>\n<body>\n'
  cat src/page.html
  printf '\n</body>\n</html>\n'
} > public/index.html
cp assets/* public/
cat > public/404.html <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Not found · cvengine.live</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.6 system-ui,sans-serif;background:#f3f4f6;color:#0b0c0e}@media (prefers-color-scheme:dark){body{background:#0d0e10;color:#f1f2f4}}a{color:inherit}</style></head>
<body><p>That page does not exist. <a href="/">Go to cvengine.live</a></p></body></html>
HTML
echo "built public/index.html ($(wc -c < public/index.html) bytes)"
