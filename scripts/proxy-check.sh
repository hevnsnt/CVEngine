# shellcheck shell=bash
# Sourced by scripts/update-deploy.sh: the bundled proxy (nginx) must accept the configuration it will run with, and must answer for web once it
# runs. A proxy that nginx refuses restarts over and over, and Docker calls it "running" between two restarts, so neither `up` nor `ps` notices.
#
#   cvengine_proxy_preflight docker compose [ARGS...]
#       BEFORE anything is migrated or recreated: `nginx -t` in a throwaway container of the proxy's image with the proxy's own configuration
#       files, certificates and environment as the layout resolves them (overlays and the env file included), with no network. Prints one line
#       that starts with "proxy:". Returns 1 only when nginx itself refuses the configuration; 0 when it accepts it, when the layout has no proxy
#       service, or when the check cannot run (then it says so: it never blocks an update for a reason of its own).
#   cvengine_proxy_verify docker compose [ARGS...]
#       AFTER the restart: `nginx -t` in the running proxy, a restart count that does not move while it is watched, and one request through the
#       proxy to the web service (the client address probe route, which passes the maintenance page and which only the web service answers;
#       an answer of 500 or more, 502 when web cannot be reached, or none at all is a failure). CVENGINE_VERIFY_PROXY_TRIES (default 15) tries,
#       CVENGINE_VERIFY_POLL seconds apart. Prints one line that starts with "proxy:"; returns 1 when the proxy never passes.

cvengine_proxy_preflight() {
  local config
  config=$("$@" config --format json 2>/dev/null) || { echo "proxy: the layout could not be read, so the new proxy configuration was not checked before the update"; return 0; }
  CV_PROXY_CONFIG="$config" python3 - <<'PY'
import json, os, subprocess, sys
try:
    cfg = json.loads(os.environ['CV_PROXY_CONFIG'])
except ValueError:
    print('proxy: the layout could not be read, so the new proxy configuration was not checked before the update')
    sys.exit(0)
svc = (cfg.get('services') or {}).get('proxy')
if not svc or not svc.get('image'):
    sys.exit(0)  # a layout without the bundled proxy (the dev stack)
args = ['docker', 'run', '--rm', '--network', 'none', '--name', f'cvengine-proxy-preflight-{os.getpid()}']
env = dict(os.environ)
for mount in svc.get('volumes') or []:
    if mount.get('type') == 'bind' and mount.get('source') and mount.get('target'):
        args += ['-v', f"{mount['source']}:{mount['target']}:ro"]
for secret in svc.get('secrets') or []:
    path = ((cfg.get('secrets') or {}).get(secret.get('source')) or {}).get('file')
    target = secret.get('target') or secret.get('source')
    if path and target:
        args += ['-v', f"{path}:{target if target.startswith('/') else '/run/secrets/' + target}:ro"]
for name, value in (svc.get('environment') or {}).items():
    env[name] = '' if value is None else str(value)
    args += ['-e', name]  # the value travels in the environment of this call, never on a command line
args += [svc['image'], 'nginx', '-t']
try:
    run = subprocess.run(args, env=env, capture_output=True, text=True, timeout=180)
except (OSError, subprocess.SubprocessError) as exc:
    print(f'proxy: the configuration check could not run ({exc.__class__.__name__}); not checked before the update')
    sys.exit(0)
out = (run.stdout or '') + (run.stderr or '')
if run.returncode == 0:
    print('proxy: nginx accepts the new configuration (nginx -t, before anything is migrated or recreated)')
    sys.exit(0)
refused = [line.strip() for line in out.splitlines() if '[emerg]' in line or 'test failed' in line]
if refused:
    print(f'proxy: nginx refuses the new configuration: {refused[0]}')
    sys.exit(1)
last = [line.strip() for line in out.splitlines() if line.strip()][-1:] or ['no output']
print(f'proxy: the configuration check could not run ({last[0][:200]}); not checked before the update')
sys.exit(0)
PY
}

cvengine_proxy_verify() {
  local compose=("$@") attempt id before after code said=''
  for attempt in $(seq 1 "${CVENGINE_VERIFY_PROXY_TRIES:-15}"); do
    id=$("${compose[@]}" ps -q proxy 2>/dev/null | head -n 1 || true)
    before=''
    [ -z "$id" ] || before=$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null || true)
    if said=$("${compose[@]}" exec -T proxy nginx -t 2>&1); then
      # through the proxy to web: only the web service answers this route, and it passes the maintenance page (config/nginx/cvengine.conf)
      code=$("${compose[@]}" exec -T proxy sh -c 'command -v curl >/dev/null 2>&1 || { echo nocurl; exit 0; }; curl -sk -o /dev/null -w "%{http_code}" --max-time 10 https://127.0.0.1/client-address-probe/update-verify/' 2>/dev/null | tr -dc '0-9a-z' || true)
      sleep "${CVENGINE_VERIFY_POLL:-2}"
      after=''
      [ -z "$id" ] || after=$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null || true)
      if [ "$before" != "$after" ]; then
        said="the proxy container restarted while it was watched (restart count ${before:-?} then ${after:-?})"
      elif [ "$code" = nocurl ]; then
        echo "proxy: nginx accepts its configuration and stays up (no curl in the proxy image, so the request through it was not sent)"
        return 0
      elif [[ $code =~ ^[1-4][0-9][0-9]$ ]]; then
        echo "proxy: up, and a request through it reached the web service (status $code)"
        return 0
      else
        said="a request through the proxy to the web service got ${code:-no answer} (502 or 504: the proxy cannot reach web)"
      fi
    fi
    sleep "${CVENGINE_VERIFY_POLL:-2}"
  done
  said=$(printf '%s\n' "$said" | grep -iE 'emerg|error|restart|request' | tail -n 1 || true)
  [ -n "$said" ] || said=$("${compose[@]}" logs --tail 20 proxy 2>/dev/null | grep -iE 'emerg|error' | tail -n 1 || true)
  echo "proxy: after the restart the proxy does not answer for the site: ${said:-see docker compose logs proxy}"
  return 1
}
